"""Summaries of the audit log: counts per decision, per rule and per tool."""

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from cc_firewall.audit import ROTATE_KEEP, audit_path

TOP_TOOLS = 5


@dataclass
class Stats:
    """Counts gathered from the audit log."""

    records: int = 0
    malformed: int = 0
    decisions: Counter[str] = field(default_factory=Counter)
    rules: Counter[str] = field(default_factory=Counter)
    tools: Counter[str] = field(default_factory=Counter)


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


def has_rule(line: str, rule_id: str) -> bool:
    """Return True if the line is a valid record that names ``rule_id`` among its rules."""
    record = parse_record(line)
    return record is not None and rule_id in record["rules"]


def _log_files() -> list[Path]:
    path = audit_path()
    rotated = [path.with_name(f"{path.name}.{n}") for n in range(ROTATE_KEEP, 0, -1)]
    return [p for p in [*rotated, path] if p.exists()]


def collect(since: date | None = None) -> Stats:
    """Count the records in the audit log and its rotated files, from ``since`` on if given."""
    stats = Stats()
    for path in _log_files():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            record = parse_record(line)
            if record is None:
                stats.malformed += 1
                continue
            if since is not None and record["ts"][:10] < since.isoformat():
                continue
            stats.records += 1
            stats.decisions[record["decision"]] += 1
            stats.rules.update(record["rules"])
            stats.tools[record["tool"]] += 1
    return stats


def _section(title: str, counts: list[tuple[str, int]]) -> list[str]:
    if not counts:
        return [f"{title}: none"]
    width = max(len(name) for name, _ in counts)
    return [f"{title}:", *(f"  {name:<{width}}  {n}" for name, n in counts)]


def format_stats(stats: Stats) -> str:
    """Return the report printed by ``cc-firewall stats``."""
    lines = [f"records: {stats.records}"]
    if stats.malformed:
        lines[0] += f" (skipped {stats.malformed} malformed lines)"
    lines += _section("decisions", stats.decisions.most_common())
    lines += _section("rules", stats.rules.most_common())
    lines += _section(f"top {TOP_TOOLS} tools", stats.tools.most_common(TOP_TOOLS))
    return "\n".join(lines)
