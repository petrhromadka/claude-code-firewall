"""Check that the installed hook, its interpreter, the policy and the audit log all work."""

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
from cc_firewall.policy import PolicyError, default_policy_path, load_policy

Check = tuple[str, str, str]  # (status, name, detail); status is OK or FAIL


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
    policy = policy or _installed_policy(argv) or default_policy_path()
    if not all(_is_current(h, policy) for h in handlers):
        yield "FAIL", "hook", "entry is stale; run cc-firewall install to refresh it"
    else:
        yield "OK", "hook", f"current, shell {handlers[0]['shell']}"
    interpreter = Path(argv[0]) if argv else None
    if interpreter is not None and interpreter.is_file():
        yield "OK", "interpreter", str(interpreter)
    else:
        yield "FAIL", "interpreter", f"{interpreter} does not exist"
    try:
        run_self_test(handlers[0])
    except SelfTestError as exc:
        yield "FAIL", "self-test", str(exc)
    else:
        yield "OK", "self-test", "hook command ran and exited 0"
    yield from _policy_check(policy)


def _policy_check(policy: Path) -> Iterator[Check]:
    try:
        loaded = load_policy(policy, required=True)
    except PolicyError as exc:
        yield "FAIL", "policy", "; ".join(exc.errors)
    else:
        yield "OK", "policy", f"{policy}: {len(loaded.rules)} rules, mode {loaded.mode}"


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
    Without a hook entry the policy is still checked, at ``policy`` or the default path.
    """
    checks = list(_hook_checks(settings_path, policy))
    if not any(name == "policy" for _, name, _ in checks):
        checks.extend(_policy_check(policy or default_policy_path()))
    checks.append(_audit_check())
    return checks


def doctor(settings_path: Path, policy: Path | None = None) -> tuple[str, int]:
    """Return the checklist text and exit code: 1 if any check failed, else 0.

    Each check is one ``OK`` or ``FAIL`` line; a multi-line detail continues indented.
    """
    checks = run_checks(settings_path, policy)
    lines = [
        f"{status:<4} {name}: {detail.strip()}".replace("\n", "\n     ")
        for status, name, detail in checks
    ]
    failed = any(status == "FAIL" for status, _, _ in checks)
    return "\n".join(lines), int(failed)
