"""Check that the installed hook, its interpreter, the policy and the audit log all work."""

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

from cc_firewall.audit import audit_path
from cc_firewall.install import (
    SHELLS,
    SelfTestError,
    hook_argv,
    hook_entry,
    load_settings,
    our_handlers,
)
from cc_firewall.install import self_test as run_self_test
from cc_firewall.policy import PolicyError, default_policy_path, load_policy, slow_regex_warnings

Check = tuple[str, str, str]  # (status, name, detail); status is OK, FAIL, WARN or NOTE


def _is_current(handler: dict[str, object], policy: Path) -> bool:
    shell = handler.get("shell")
    return shell in SHELLS and handler == hook_entry(policy.absolute(), str(shell))


def _installed_policy(argv: list[str]) -> Path | None:
    if "--policy" in argv[:-1]:
        return Path(argv[argv.index("--policy") + 1])
    return None


def _hook_checks(settings_path: Path, policy: Path | None) -> Iterator[Check]:
    try:
        settings = load_settings(settings_path)
    except (OSError, ValueError) as exc:
        yield "FAIL", "settings", str(exc)
        return
    if not settings_path.exists():
        yield "FAIL", "settings", f"{settings_path} does not exist"
        return
    yield "OK", "settings", f"{settings_path} is valid JSON"
    handlers = our_handlers(settings)
    if not handlers:
        yield "FAIL", "hook", f"no cc-firewall hook in {settings_path}; run cc-firewall install"
        return
    argv = hook_argv(handlers[0])
    installed = (_installed_policy(argv) or default_policy_path()).absolute()
    stored_shell = handlers[0].get("shell")
    shell = stored_shell if stored_shell in SHELLS else "bash"
    if not all(_is_current(h, installed) for h in handlers):
        yield "FAIL", "hook", "entry is stale; run cc-firewall install to refresh it"
    else:
        yield "OK", "hook", f"current, shell {shell}"
    yield _interpreter_check(argv)
    yield _self_test_check(hook_entry(installed, str(shell)))
    if policy is not None and policy.absolute() != installed:
        yield "NOTE", "policy", f"checking {policy}, but the installed hook reads {installed}"
    yield from _policy_check(policy or installed)


def _interpreter_check(argv: list[str]) -> Check:
    found = argv[0] if argv and Path(argv[0]).is_file() else None
    found = found or (shutil.which(argv[0]) if argv else None)
    if found is None:
        return "FAIL", "interpreter", f"{argv[0] if argv else '(none)'} does not exist"
    return "OK", "interpreter", found


def _self_test_check(handler: dict[str, object]) -> Check:
    """Run the hook command rebuilt for this interpreter, never the one stored in settings.

    The stored command may come from a copied or cloned settings file; running it would run
    whatever it names.
    """
    try:
        run_self_test(handler)
    except SelfTestError as exc:
        return "FAIL", "self-test", str(exc)
    return "OK", "self-test", "hook command ran and exited 0"


def _policy_check(policy: Path) -> Iterator[Check]:
    try:
        loaded = load_policy(policy, required=True)
    except PolicyError as exc:
        yield "FAIL", "policy", "; ".join(exc.errors)
        return
    yield "OK", "policy", f"{policy}: {len(loaded.rules)} rules, mode {loaded.mode}"
    for warning in slow_regex_warnings(loaded):
        yield "WARN", "policy", warning


def _audit_check() -> Check:
    directory = audit_path().parent
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=directory):
            pass
    except OSError as exc:
        return "FAIL", "audit", f"{directory} is not writable: {exc}"
    return "OK", "audit", f"{directory} is writable"


def run_checks(settings_path: Path, policy: Path | None = None) -> list[Check]:
    """Run every check and return the results in order.

    ``policy`` defaults to the path the installed hook uses, else the default policy path.
    It only selects the file for the policy check; whether the hook is stale is judged
    against the path the hook reads. Without a hook entry the policy is still checked, at
    ``policy`` or the default path.
    """
    checks = list(_hook_checks(settings_path, policy))
    if not any(name == "policy" for _, name, _ in checks):
        checks.extend(_policy_check(policy or default_policy_path()))
    checks.append(_audit_check())
    return checks


def doctor(settings_path: Path, policy: Path | None = None) -> tuple[str, int]:
    """Return the checklist text and exit code: 1 if any check failed, else 0.

    Each check is one ``OK``, ``FAIL``, ``WARN`` or ``NOTE`` line; a multi-line detail
    continues indented. Only ``FAIL`` lines set the exit code.
    """
    checks = run_checks(settings_path, policy)
    lines = [
        f"{status:<4} {name}: {detail.strip()}".replace("\n", "\n     ")
        for status, name, detail in checks
    ]
    failed = any(status == "FAIL" for status, _, _ in checks)
    return "\n".join(lines), int(failed)
