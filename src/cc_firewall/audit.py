"""Redacted JSONL audit log with simple size-based rotation."""

import contextlib
import json
import os
import secrets
import stat
import sys
import time
import unicodedata
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
# A lock dated further in the future than this is stale too; the slack absorbs clock granularity.
FUTURE_LOCK_SLACK = 1.0
# Refuse to follow a symlink planted at the log or lock path (POSIX only).
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


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
        "session_id": redact(hook.session_id, os.environ) if hook else "",
        "cwd": redact(hook.cwd, os.environ) if hook else "",
        "tool": redact(hook.tool, os.environ) if hook else "",
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
        # ASCII only: control and bidi characters from tool input stay escaped in the file, so
        # printing the log can't reach the terminal with them. Lone surrogates are escaped too.
        data = (json.dumps(record, ensure_ascii=True) + "\n").encode("ascii")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | O_NOFOLLOW | getattr(os, "O_BINARY", 0)
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
    token = secrets.token_hex(8)
    if not _acquire(lock, token):
        return
    try:
        if path.stat().st_size > MAX_LOG_BYTES:  # another hook may have rotated meanwhile
            _rotate(path)
    finally:
        _release(lock, token)


def _create_lock(lock: Path, token: str) -> bool:
    """Create ``lock`` holding ``token``; False if anything is already at that path."""
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
    except OSError:  # FileExistsError, or PermissionError for a directory on Windows
        return False
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)
    return True


def _is_stale(lock: Path) -> bool:
    """Return True for a lock left by a killed hook: old, dated in the future, or a directory."""
    try:
        info = lock.lstat()
    except OSError:
        return False
    age = time.time() - info.st_mtime
    return stat.S_ISDIR(info.st_mode) or not -FUTURE_LOCK_SLACK <= age < STALE_LOCK_SECONDS


def _acquire(lock: Path, token: str) -> bool:
    """Take the lock, taking over a stale one; False if another hook holds it.

    A stale lock is first renamed to a name unique to this hook. Of two hooks that find the same
    stale lock only one rename succeeds, and a hook that moved a live lock puts it back.
    """
    if _create_lock(lock, token):
        return True
    if not _is_stale(lock):
        return False
    moved = lock.with_name(f"{lock.name}.{token}")
    try:
        lock.replace(moved)
    except OSError:
        return False
    if not _is_stale(moved):  # another hook took over first and this rename moved its lock
        with contextlib.suppress(OSError):
            moved.replace(lock)
        return False
    with contextlib.suppress(OSError):
        if moved.is_dir():
            moved.rmdir()  # a non-empty directory is left under its new name
        else:
            moved.unlink()
    return _create_lock(lock, token)


def _release(lock: Path, token: str) -> None:
    """Remove the lock only if it is still the one this hook created."""
    with contextlib.suppress(OSError):
        if lock.read_text(encoding="ascii") == token:
            lock.unlink()


def _rotate(path: Path) -> None:
    """Shift ``audit.jsonl`` to ``.1`` and older generations up to ``.ROTATE_KEEP``."""
    for n in range(ROTATE_KEEP - 1, 0, -1):
        older = path.with_name(f"{path.name}.{n}")
        if older.exists():
            older.replace(path.with_name(f"{path.name}.{n + 1}"))
    path.replace(path.with_name(f"{path.name}.1"))


def log_files() -> list[Path]:
    """Return the existing audit log files, oldest first: rotated ones, then the current one."""
    path = audit_path()
    rotated = [path.with_name(f"{path.name}.{n}") for n in range(ROTATE_KEEP, 0, -1)]
    return [p for p in [*rotated, path] if p.exists()]


def read_lines() -> list[str]:
    r"""Return the non-blank lines of all log files, oldest first.

    Undecodable bytes become U+FFFD instead of failing the read. Lines are split on ``\n``
    only, so a U+2028 or U+0085 inside a record does not cut it in two.
    """
    lines: list[str] = []
    for path in log_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        lines += [line for line in text.split("\n") if line.strip()]
    return lines


def parse_record(line: str) -> dict[str, Any] | None:
    """Return the audit record on one line, or None if the line is not a valid record."""
    try:
        record = json.loads(line)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    fields_ok = (
        isinstance(record.get("ts"), str)
        and isinstance(record.get("decision"), str)
        and isinstance(record.get("tool"), str)
        and isinstance(record.get("rules"), list)
        and all(isinstance(r, str) for r in record["rules"])
    )
    return record if fields_ok else None


BMP_MAX = 0xFFFF


def terminal_safe(text: str) -> str:
    r"""Escape control and format characters (categories Cc and Cf) as ``\uXXXX``.

    This keeps escape sequences and bidi overrides from a log line out of the terminal. A
    character above U+FFFF, such as a tag character, becomes ``\UXXXXXXXX``.
    """
    return "".join(_escape(c) if unicodedata.category(c) in ("Cc", "Cf") else c for c in text)


def _escape(char: str) -> str:
    code = ord(char)
    return f"\\u{code:04x}" if code <= BMP_MAX else f"\\U{code:08x}"
