"""The PreToolUse hook: parse the payload, evaluate, log, and format the decision.

This module is the whole hook path, so it imports only what that path needs; ``__main__``
calls :func:`fast_main` before the full CLI (argparse, install) is loaded.
"""

import faulthandler
import json
import os
import sys
import threading
from pathlib import Path
from typing import IO, NoReturn

from cc_firewall.audit import O_NOFOLLOW, audit_path, log_decision
from cc_firewall.engine import evaluate
from cc_firewall.models import HookInput, Policy
from cc_firewall.policy import PolicyError, default_policy_path, load_policy

DEFAULT_DEADLINE = 5.0
# The watchdog that kills the process if the deadline path itself can't run, see run_hook.
HARD_STOP_GRACE = 1.0
# The watchdog writes its thread dump here, in the audit directory, not to stderr.
WATCHDOG_LOG = "watchdog.log"


def parse_hook_input(raw: str) -> HookInput:
    """Parse the hook JSON payload.

    Raises:
        ValueError: The payload is not a JSON object with a string ``tool_name``.
    """
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("tool_name"), str):
        raise ValueError("hook payload must be an object with a string 'tool_name'")
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        raise ValueError("'tool_input' must be an object")
    return HookInput(
        tool=data["tool_name"],
        tool_input=tool_input,
        session_id=str(data.get("session_id", "")),
        cwd=str(data.get("cwd", "")),
    )


def format_output(decision: str, reason: str) -> str:
    """Return the hook stdout JSON for a deny or ask decision."""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )


class _Progress:
    """What the worker has learned so far, for the record written if the deadline expires.

    The worker and the deadline path both may log; :meth:`claim` lets only the first one do it,
    so a worker that finishes just as the deadline expires can't add a second record.
    """

    def __init__(self) -> None:
        self.hook: HookInput | None = None
        self.policy = "invalid"
        self._lock = threading.Lock()
        self._claimed = False

    def claim(self) -> bool:
        """Return True to the first caller only; that caller decides and logs."""
        with self._lock:
            first, self._claimed = not self._claimed, True
            return first

    def log(self, hook: HookInput | None, decision: str, rules: tuple[str, ...] = ()) -> None:
        """Log the worker's decision unless the deadline path has claimed the outcome."""
        if self.claim():
            log_decision(hook, decision, rules, self.policy)


def deadline_seconds() -> float:
    """Return the evaluation deadline.

    ``CC_FIREWALL_DEADLINE`` exists for tests. It can only shorten the default, so a stray
    value can't push the hook past Claude Code's own timeout, which would run the tool.
    """
    try:
        value = float(os.environ.get("CC_FIREWALL_DEADLINE", ""))
    except ValueError:
        return DEFAULT_DEADLINE
    return value if 0 < value < DEFAULT_DEADLINE else DEFAULT_DEADLINE


def _fail_closed(progress: _Progress, reason: str) -> str:
    progress.log(progress.hook, "deny")
    return format_output("deny", f"cc-firewall: {reason}")


def _load(policy_path: Path | None) -> tuple[Policy, str]:
    path = policy_path or default_policy_path()
    policy = load_policy(path, required=policy_path is not None)
    return policy, "ok" if path.exists() else "missing"


def _decide(stdin: IO[bytes], policy_path: Path | None, progress: _Progress) -> str | None:
    """Evaluate one payload; any problem yields a deny. Fills ``progress`` as it goes."""
    policy, problem = None, ""
    try:
        policy, progress.policy = _load(policy_path)
    except PolicyError as exc:
        problem = f"unusable policy, denying all tool calls: {exc}"
    except Exception as exc:  # fail closed on anything unexpected
        problem = f"internal error, denying tool call: {type(exc).__name__}: {exc}"
    try:
        hook = progress.hook = parse_hook_input(stdin.read().decode("utf-8"))
        if policy is None:
            return _fail_closed(progress, problem)
        verdict = evaluate(policy, hook.tool, hook.tool_input, cwd=hook.cwd or None)
    except Exception as exc:  # fail closed on anything unexpected
        return _fail_closed(
            progress, f"internal error, denying tool call: {type(exc).__name__}: {exc}"
        )
    if verdict.decision == "allow":
        if policy.log_allowed:
            progress.log(hook, "allow")
        return None
    if policy.mode == "audit":
        progress.log(hook, f"would-{verdict.decision}", verdict.rules)
        return None
    progress.log(hook, verdict.decision, verdict.rules)
    return format_output(verdict.decision, verdict.reason)


def _expire(progress: _Progress) -> NoReturn:
    """Deny, log a short record and exit at once; the stuck worker must not keep us alive."""
    reason = "cc-firewall: evaluation exceeded deadline, denying tool call"
    sys.stdout.write(format_output("deny", reason) + "\n")
    sys.stdout.flush()
    log_decision(progress.hook, "deny", (), progress.policy, include_input=False)
    os._exit(0)


def _open_watchdog_log() -> int | None:
    """Open the watchdog dump file in the audit directory; None if that fails."""
    try:
        directory = audit_path().parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | O_NOFOLLOW
        return os.open(directory / WATCHDOG_LOG, flags, 0o600)
    except (OSError, RuntimeError):  # RuntimeError: Path.home() found no home directory
        return None


def run_hook(stdin: IO[bytes], policy_path: Path | None = None) -> str | None:
    """Read one hook payload from ``stdin`` and return the stdout text, or None for no decision.

    An unreadable or malformed payload, a missing explicit ``policy_path``, an invalid policy
    or any internal error yields a deny (fail closed).

    Evaluation runs in a daemon thread under :func:`deadline_seconds`, because Claude Code runs
    the tool when a hook times out. A stall that releases the GIL (a blocked read) ends in a
    deny printed by :func:`_expire`. A regex that backtracks holds the GIL, so neither ``join``
    nor ``_expire`` can run; the ``faulthandler`` watchdog runs in a C thread and exits with
    status 1 instead, which the installed ``|| exit 2`` turns into a block. No Python code runs
    on that path, so it writes no audit record and nothing to stderr; its thread dump goes to
    ``watchdog.log`` in the audit directory, or to stderr if that file can't be opened.
    """
    deadline = deadline_seconds()
    progress = _Progress()
    result: list[str | None] = []
    worker = threading.Thread(
        target=lambda: result.append(_decide(stdin, policy_path, progress)), daemon=True
    )
    dump_fd = _open_watchdog_log()
    dump_file = sys.stderr if dump_fd is None else dump_fd
    faulthandler.dump_traceback_later(deadline + HARD_STOP_GRACE, exit=True, file=dump_file)
    try:
        worker.start()
        worker.join(deadline)
        if worker.is_alive() and progress.claim():
            _expire(progress)
        worker.join()  # the worker claimed the outcome and is finishing; the watchdog still runs
    finally:
        faulthandler.cancel_dump_traceback_later()
        if dump_fd is not None:
            os.close(dump_fd)
    return result[0]


def main(policy_path: Path | None) -> int:
    """Run the hook on the process stdin and stdout; the exit status is always 0."""
    output = run_hook(sys.stdin.buffer, policy_path)
    if output is not None:
        sys.stdout.write(output + "\n")
    return 0


def fast_main(argv: list[str]) -> int | None:
    """Run ``hook`` without loading the CLI when argv is ``hook [--policy PATH]``.

    Returns None for any other argv, which the full argparse CLI then handles.
    """
    match argv:
        case ["hook"]:
            return main(None)
        case ["hook", "--policy", path] if not path.startswith("-"):
            return main(Path(path))
        case ["hook", arg] if arg.startswith("--policy="):
            return main(Path(arg.removeprefix("--policy=")))
    return None
