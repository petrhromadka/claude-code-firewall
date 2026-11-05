"""Install or remove the firewall as a PreToolUse hook in Claude Code's settings.json."""

import contextlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any

from cc_firewall.policy import PolicyError, load_policy, slow_regex_warnings

SHELLS = ("bash", "powershell")
HOOK_TIMEOUT = 30
SELF_TEST_TIMEOUT = HOOK_TIMEOUT

_MODULE_ARGS = ["-m", "cc_firewall", "hook"]
_CONSOLE_SCRIPTS = ("cc-firewall", "cc-firewall.exe")
# PowerShell ends a single-quoted string at any of these and reads a doubled one as literal.
_PS_QUOTES = "'\u2018\u2019\u201a\u201b"
_PS_TOKEN = re.compile(
    f"[{_PS_QUOTES}]((?:[^{_PS_QUOTES}]|[{_PS_QUOTES}]{{2}})*)[{_PS_QUOTES}]|([^\\s;{_PS_QUOTES}]+)"
)
_PS_QUOTE_CHAR = re.compile(f"([{_PS_QUOTES}])")
_PS_DOUBLED = re.compile(f"[{_PS_QUOTES}]([{_PS_QUOTES}])")
# A deny for these reasons means the hook cannot use its policy and would deny every call.
_FAIL_CLOSED = ("unusable policy", "internal error")
_HINT = (
    "hint: the hook runs Python with -I (isolated), which ignores user site-packages and "
    "PYTHONPATH. Install cc-firewall with `uv tool install` or `pipx`, or into a virtual "
    "environment, and run `install` with that interpreter."
)


class SelfTestError(Exception):
    """The hook command failed its self-test, so it was not written."""


def default_settings_path() -> Path:
    """Return the user-level Claude Code settings path."""
    return Path.home() / ".claude" / "settings.json"


def _ps_quote(text: str) -> str:
    return "'" + _PS_QUOTE_CHAR.sub(r"\1\1", text) + "'"


def hook_entry(policy: Path, shell: str = "bash") -> dict[str, Any]:
    """Return the hook handler that runs the firewall with ``policy`` (an absolute path).

    ``-I`` runs Python isolated: the project directory Claude Code starts the hook in is not
    put on ``sys.path``, so a planted ``cc_firewall/`` or ``json.py`` there cannot replace the
    firewall's code; ``PYTHON*`` variables and user site-packages are ignored as well.

    Claude Code treats exit codes other than 0 and 2 as non-blocking errors and runs the tool
    anyway. The hook's own errors already end in a deny, so the command turns any other
    failure into exit 2: a missing interpreter, an uninstalled package or a crash before the
    hook code runs. That needs a shell, so this is shell form rather than exec-form ``args``,
    and ``shell`` is set explicitly: Claude Code otherwise picks Git Bash on Windows, or
    PowerShell when Git Bash is not installed, and the ``|| exit 2`` form does not parse in
    Windows PowerShell 5.1. With ``shell="powershell"`` the command is
    ``& '<python>' ...; if ($LASTEXITCODE -ne 0) { exit 2 }``, which parses in PowerShell 5.1
    and 7 but is not valid ``sh``, so it only suits Windows machines without Git Bash or
    users who prefer PowerShell; the install self-test runs it through the same shell.
    ``onFailure: "block"`` (Claude Code 2.1.295 and later) makes Claude Code block the tool
    call when the hook fails to run or times out, instead of reporting a non-blocking error.
    With it, a 30 second ``timeout`` ends a stuck hook sooner and still blocks. Older versions
    rely on the ``exit 2`` fallback alone, and a hook timeout there lets the tool run.
    """
    if shell not in SHELLS:
        raise ValueError(f"shell must be one of {', '.join(SHELLS)}")
    if shell == "bash":
        argv = [sys.executable, "-I", "-m", "cc_firewall", "hook", "--policy", str(policy)]
        command = f"{shlex.join(argv)} || exit 2"
    else:
        python, policy_arg = _ps_quote(sys.executable), _ps_quote(str(policy))
        command = (
            f"& {python} -I -m cc_firewall hook --policy {policy_arg}; "
            "if ($LASTEXITCODE -ne 0) { exit 2 }"
        )
    return {
        "type": "command",
        "shell": shell,
        "command": command,
        "onFailure": "block",
        "timeout": HOOK_TIMEOUT,
    }


def hook_argv(handler: dict[str, Any]) -> list[str]:
    """Return the argument vector a handler runs, best effort: interpreter first."""
    command = str(handler.get("command", ""))
    args = handler.get("args")
    if isinstance(args, list):
        return [command, *map(str, args)]
    if handler.get("shell") == "powershell":
        tokens = [
            bare or _PS_DOUBLED.sub(r"\1", quoted) for quoted, bare in _PS_TOKEN.findall(command)
        ]
        return tokens[1:] if tokens[:1] == ["&"] else tokens
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def is_ours(hook: object) -> bool:
    """Return True if ``hook`` is a handler that runs the firewall.

    That is ``<interpreter> [options] -m cc_firewall hook ...`` or ``cc-firewall hook ...``,
    matched on argument tokens, so a command that only mentions the name is not ours.
    """
    if not isinstance(hook, dict):
        return False
    argv = hook_argv(hook)
    if argv[1:2] == ["hook"] and PureWindowsPath(argv[0]).name.lower() in _CONSOLE_SCRIPTS:
        return True
    size = len(_MODULE_ARGS)
    return any(argv[i : i + size] == _MODULE_ARGS for i in range(1, len(argv)))


def _pre_tool_use(settings: dict[str, Any]) -> list[Any]:
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' in settings must be an object")
    entries = hooks.setdefault("PreToolUse", [])
    if not isinstance(entries, list):
        raise ValueError("'hooks.PreToolUse' in settings must be a list")
    return entries


def _handler_lists(entries: list[Any]) -> list[list[Any]]:
    handlers = [e.get("hooks") for e in entries if isinstance(e, dict)]
    return [h for h in handlers if isinstance(h, list)]


def our_handlers(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the firewall handlers in ``hooks.PreToolUse``, without changing ``settings``."""
    hooks = settings.get("hooks")
    entries = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    if not isinstance(entries, list):
        return []
    return [h for handlers in _handler_lists(entries) for h in handlers if is_ours(h)]


def add_hook(settings: dict[str, Any], expected: dict[str, Any]) -> bool:
    """Add the ``expected`` handler or rewrite a stale one in place. Return False if current.

    The first firewall handler is rewritten and any later ones are dropped, together with a
    matcher group they leave empty.

    Raises:
        ValueError: ``hooks`` or ``hooks.PreToolUse`` exists with an unexpected type.
    """
    entries = _pre_tool_use(settings)
    found = changed = False
    emptied: list[list[Any]] = []
    for handlers in _handler_lists(entries):
        kept = [h for h in handlers if not is_ours(h)]
        first = next((i for i, h in enumerate(handlers) if is_ours(h)), None)
        if first is not None and not found:
            found = True
            kept.insert(first, expected)
        if kept != handlers:
            changed = True
            emptied += [handlers] if not kept else []
            handlers[:] = kept
    entries[:] = [
        e
        for e in entries
        if not (isinstance(e, dict) and any(e.get("hooks") is h for h in emptied))
    ]
    if not found:
        entries.append({"matcher": "*", "hooks": [expected]})
    return changed or not found


def remove_hook(settings: dict[str, Any]) -> bool:
    """Remove the firewall handlers and any container they leave empty. Return True if any.

    Only containers that held a firewall handler are dropped; other empty ones stay.
    """
    if not our_handlers(settings):
        return False
    hooks = settings["hooks"]
    entries = hooks["PreToolUse"]
    for entry in list(entries):
        handlers = entry.get("hooks") if isinstance(entry, dict) else None
        if isinstance(handlers, list) and any(is_ours(h) for h in handlers):
            handlers[:] = [h for h in handlers if not is_ours(h)]
            if not handlers:
                entries.remove(entry)
    if not entries:
        del hooks["PreToolUse"]
    if not hooks:
        del settings["hooks"]
    return True


def _reject_constant(name: str) -> None:
    raise ValueError(f"non-standard JSON value {name}")


def load_settings(path: Path) -> dict[str, Any]:
    """Read a settings file; a missing one is empty.

    Raises:
        ValueError: The file is not JSON, not an object, or holds NaN or Infinity.
    """
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8-sig")
    try:
        loaded = json.loads(text, parse_constant=_reject_constant)
    except ValueError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return loaded


def _write_atomic(path: Path, text: str) -> None:
    """Replace the file behind ``path`` (following symlinks) with ``text`` in one step."""
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        if target.exists():
            shutil.copymode(target, tmp)
        Path(tmp).replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def _backup(path: Path) -> None:
    """Copy ``path`` to ``<name>.bak`` beside it, replacing a symlink there, never its target.

    Raises:
        OSError: ``<name>.bak`` exists and is neither a regular file nor a symlink.
    """
    bak = path.with_name(path.name + ".bak")
    with contextlib.suppress(FileNotFoundError):
        mode = bak.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
            raise OSError(f"{bak} is not a regular file; not overwriting it")
    fd, tmp = tempfile.mkstemp(dir=bak.parent, prefix=f".{bak.name}.", suffix=".tmp")
    os.close(fd)
    try:
        shutil.copy2(path, tmp)
        Path(tmp).replace(bak)  # replaces a symlink itself, so its target is never written
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def _save(path: Path, settings: dict[str, Any]) -> None:
    rendered = json.dumps(settings, indent=2, ensure_ascii=False)
    if path.exists():
        _backup(path)
    _write_atomic(path, rendered + "\n")


def _section(settings: dict[str, Any]) -> str:
    """Render ``hooks.PreToolUse`` as it will be written, or say which key is removed."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return 'the "hooks" key is removed'
    if "PreToolUse" not in hooks:
        return 'the "hooks.PreToolUse" key is removed'
    return json.dumps({"hooks": {"PreToolUse": hooks["PreToolUse"]}}, indent=2, ensure_ascii=False)


def _git_bash() -> str | None:
    override = os.environ.get("CLAUDE_CODE_GIT_BASH_PATH")
    if override:
        return override
    git = shutil.which("git")
    if git is not None:
        exe = Path(git).resolve()
        for parent in exe.parents[1:3]:
            bash = parent / "bin" / "bash.exe"
            if bash.is_file():
                return str(bash)
    bash = shutil.which("bash")  # the one in System32 is WSL, not Git Bash
    return bash if bash and "system32" not in bash.lower() else None


def shell_argv(shell: str, command: str) -> list[str]:
    """Return the argv that runs ``command`` the way Claude Code does for ``shell``.

    Raises:
        SelfTestError: The shell cannot be found.
    """
    if shell == "powershell":
        exe = shutil.which("pwsh") or shutil.which("powershell")
        if exe is None:
            raise SelfTestError("cannot find pwsh or powershell")
        return [exe, "-NoProfile", "-NonInteractive", "-Command", command]
    exe = _git_bash() if sys.platform == "win32" else shutil.which("sh")
    if exe is None:
        raise SelfTestError(
            "cannot find Git Bash; install Git for Windows, set CLAUDE_CODE_GIT_BASH_PATH, "
            "or use --shell powershell"
        )
    return [exe, "-c", command]


def self_test(handler: dict[str, Any]) -> None:
    """Run ``handler`` once with a harmless Read payload, as Claude Code would.

    The audit log goes to a temporary directory, so the real one gets no test record.

    Raises:
        SelfTestError: The command did not exit 0 with empty output or hook JSON, or it denied
            the probe because it cannot use its policy.
    """
    shell = str(handler.get("shell", "bash"))
    with tempfile.TemporaryDirectory(prefix="cc-firewall-selftest-") as tmp:
        probe = Path(tmp) / "probe.txt"
        probe.write_text("cc-firewall self-test\n", encoding="utf-8")
        payload = {
            "session_id": "cc-firewall-self-test",
            "hook_event_name": "PreToolUse",
            "cwd": tmp,
            "tool_name": "Read",
            "tool_input": {"file_path": str(probe)},
        }
        if isinstance(handler.get("args"), list):
            argv = hook_argv(handler)
        else:
            argv = shell_argv(shell, str(handler.get("command", "")))
        try:
            result = subprocess.run(
                argv,
                input=json.dumps(payload).encode(),
                capture_output=True,
                cwd=tmp,
                env={**os.environ, "CC_FIREWALL_HOME": str(Path(tmp) / "audit")},
                timeout=SELF_TEST_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SelfTestError(f"hook self-test could not run: {exc}") from exc
    stdout = result.stdout.decode(errors="replace").strip()
    stderr = result.stderr.decode(errors="replace").strip()
    if result.returncode != 0:
        raise SelfTestError(f"hook self-test exited {result.returncode}:\n{stderr}\n{_HINT}")
    if stdout:
        _check_output(stdout)


def _check_output(stdout: str) -> None:
    try:
        output = json.loads(stdout)
    except ValueError:
        output = None
    specific = output.get("hookSpecificOutput") if isinstance(output, dict) else None
    if not isinstance(specific, dict):
        raise SelfTestError(f"hook self-test printed something other than hook JSON:\n{stdout}")
    reason = str(specific.get("permissionDecisionReason", ""))
    if specific.get("permissionDecision") == "deny" and any(r in reason for r in _FAIL_CLOSED):
        raise SelfTestError(f"hook self-test denied a harmless Read: {reason}")


def policy_warnings(policy: Path) -> list[str]:
    """Return the slow-regex warnings for the policy file, or none if it cannot be loaded."""
    try:
        return slow_regex_warnings(load_policy(policy))
    except PolicyError:
        return []


def install(
    path: Path, *, policy: Path, dry_run: bool, shell: str = "bash", run_self_test: bool = True
) -> str:
    """Install the hook into the settings file and return a status message.

    With ``dry_run`` the message is the resulting ``hooks.PreToolUse`` section only, so other
    settings (such as tokens in ``env``) are not printed. Before writing, the policy must load
    and the hook command is run once through ``shell`` (see :func:`self_test`), unless
    ``run_self_test`` is False: a hook whose policy is missing or invalid denies every call.

    Raises:
        ValueError: The existing settings file is not a JSON object, has odd hook types, or
            holds values (NaN, Infinity) that cannot be written back as JSON.
        SelfTestError: The policy cannot be loaded or the hook command failed its self-test;
            nothing was written.
    """
    settings = load_settings(path)
    expected = hook_entry(policy, shell)
    changed = add_hook(settings, expected)
    if dry_run:
        return _section(settings)
    if not changed:
        return f"already installed in {path}"
    if run_self_test:
        try:
            load_policy(policy, required=True)
        except PolicyError as exc:
            raise SelfTestError(
                f"create the policy first: {exc}\n(the hook denies every tool call without "
                "a valid policy; --skip-self-test installs it anyway)"
            ) from exc
        self_test(expected)
    _save(path, settings)
    return f"installed in {path}"


def uninstall(path: Path, *, dry_run: bool) -> str:
    """Remove the firewall hook from the settings file and return a status message.

    Only firewall handlers are removed, plus a matcher group, ``PreToolUse`` or ``hooks``
    left empty by that. With ``dry_run`` the message is the ``PreToolUse`` section the real
    run writes, or which key it removes.

    Raises:
        ValueError: The settings file is not valid JSON or not a JSON object.
    """
    settings = load_settings(path)
    if not remove_hook(settings):
        return f"not installed in {path}"
    if dry_run:
        return _section(settings)
    _save(path, settings)
    return f"uninstalled from {path}"
