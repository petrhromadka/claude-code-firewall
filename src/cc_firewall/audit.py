"""Redacted JSONL audit log with simple size-based rotation."""

import contextlib
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cc_firewall.models import HookInput
from cc_firewall.sensitive import redact

MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_INPUT_CHARS = 2000
ROTATE_KEEP = 3
# A rotation takes milliseconds; a lock this old was left by a process that was killed.
STALE_LOCK_SECONDS = 10.0


def audit_path() -> Path:
    """Return the audit log path; ``CC_FIREWALL_HOME`` overrides the default directory."""
    override = os.environ.get("CC_FIREWALL_HOME")
    base = Path(override) if override else Path.home() / ".claude" / "cc-firewall"
    return base / "audit.jsonl"


def build_record(
    hook: HookInput | None,
    decision: str,
    rules: tuple[str, ...],
    policy: str,
    *,
    include_input: bool = True,
) -> dict[str, Any]:
    """Build one audit record. The tool input is redacted before it is serialized and truncated.

    ``policy`` is ``"ok"``, ``"missing"`` or ``"invalid"``. Without ``include_input`` the
    record skips the input, so writing it does no regex work on untrusted text.
    """
    text = ""
    if hook and include_input:
        tool_input = redact(hook.tool_input, os.environ)
        text = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False)
    return {
        "ts": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "session_id": hook.session_id if hook else "",
        "cwd": redact(hook.cwd, os.environ) if hook else "",
        "tool": hook.tool if hook else "",
        "decision": decision,
        "policy": policy,
        "rules": list(rules),
        "input": text[:MAX_INPUT_CHARS],
    }


def log_decision(
    hook: HookInput | None,
    decision: str,
    rules: tuple[str, ...],
    policy: str,
    *,
    include_input: bool = True,
) -> None:
    """Append a record to the audit log. Any failure is swallowed; logging must not break."""
    with contextlib.suppress(Exception):
        path = audit_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            with contextlib.suppress(Exception):  # a failed rotation must not drop the record
                _rotate_locked(path)
        record = build_record(hook, decision, rules, policy, include_input=include_input)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        # backslashreplace turns a lone surrogate into a JSON escape, so the record is kept.
        data = line.encode("utf-8", errors="backslashreplace")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            if sys.platform != "win32":
                os.fchmod(fd, 0o600)  # the mode above only applies when the file is created
            os.write(fd, data)
        finally:
            os.close(fd)


def _rotate_locked(path: Path) -> None:
    """Rotate under ``audit.lock``, so two hooks never rotate at once.

    The lock is taken without waiting. A hook that finds it held skips rotation and appends;
    its record lands in the old or the new file, both of which are kept.
    """
    lock = path.with_name("audit.lock")
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if time.time() - lock.stat().st_mtime < STALE_LOCK_SECONDS:
            return
        lock.unlink()
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        if path.stat().st_size > MAX_LOG_BYTES:  # another hook may have rotated meanwhile
            _rotate(path)
    finally:
        lock.unlink()


def _rotate(path: Path) -> None:
    """Shift ``audit.jsonl`` to ``.1`` and older generations up to ``.ROTATE_KEEP``."""
    for n in range(ROTATE_KEEP - 1, 0, -1):
        older = path.with_name(f"{path.name}.{n}")
        if older.exists():
            older.replace(path.with_name(f"{path.name}.{n + 1}"))
    path.replace(path.with_name(f"{path.name}.1"))


def read_records(tail: int, decision: str | None = None) -> list[str]:
    """Return the last ``tail`` raw log lines, optionally only those with one decision."""
    path = audit_path()
    if not path.exists():
        return []
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if decision is not None:
        lines = [line for line in lines if _decision_of(line) == decision]
    return lines[-tail:] if tail > 0 else []


def _decision_of(line: str) -> str | None:
    try:
        record = json.loads(line)
    except ValueError:
        return None
    return record.get("decision") if isinstance(record, dict) else None
