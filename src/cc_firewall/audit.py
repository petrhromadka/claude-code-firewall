"""Redacted JSONL audit log with simple size-based rotation."""

import contextlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cc_firewall.models import HookInput
from cc_firewall.sensitive import redact

MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_INPUT_CHARS = 2000
ROTATE_KEEP = 3


def audit_path() -> Path:
    """Return the audit log path; ``CC_FIREWALL_HOME`` overrides the default directory."""
    override = os.environ.get("CC_FIREWALL_HOME")
    base = Path(override) if override else Path.home() / ".claude" / "cc-firewall"
    return base / "audit.jsonl"


def build_record(hook: HookInput | None, decision: str, rules: tuple[str, ...]) -> dict[str, Any]:
    """Build one audit record. The tool input is redacted before it is serialized and truncated."""
    tool_input = redact(hook.tool_input, os.environ) if hook else {}
    text = json.dumps(tool_input, separators=(",", ":"), ensure_ascii=False)
    return {
        "ts": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "session_id": hook.session_id if hook else "",
        "cwd": redact(hook.cwd, os.environ) if hook else "",
        "tool": hook.tool if hook else "",
        "decision": decision,
        "rules": list(rules),
        "input": text[:MAX_INPUT_CHARS],
    }


def log_decision(hook: HookInput | None, decision: str, rules: tuple[str, ...]) -> None:
    """Append a record to the audit log. Any failure is swallowed; logging must not break."""
    with contextlib.suppress(Exception):
        path = audit_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            _rotate(path)
        line = json.dumps(build_record(hook, decision, rules), ensure_ascii=False) + "\n"
        # backslashreplace turns a lone surrogate into a JSON escape, so the record is kept.
        data = line.encode("utf-8", errors="backslashreplace")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)


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
