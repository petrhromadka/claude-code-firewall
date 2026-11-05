"""Summaries of the audit log: counts per decision, per rule and per tool."""

from collections import Counter
from dataclasses import dataclass, field
from datetime import date

from cc_firewall.audit import parse_record, read_lines, terminal_safe

TOP_TOOLS = 5


@dataclass
class Stats:
    """Counts gathered from the audit log."""

    records: int = 0
    malformed: int = 0
    decisions: Counter[str] = field(default_factory=Counter)
    rules: Counter[str] = field(default_factory=Counter)
    tools: Counter[str] = field(default_factory=Counter)


def collect(since: date | None = None) -> Stats:
    """Count the records in the audit log and its rotated files, from ``since`` on if given."""
    stats = Stats()
    for line in read_lines():
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
    safe = [(terminal_safe(name), n) for name, n in counts]
    width = max(len(name) for name, _ in safe)
    return [f"{title}:", *(f"  {name:<{width}}  {n}" for name, n in safe)]


def format_stats(stats: Stats) -> str:
    """Return the report printed by ``cc-firewall stats``; names are made terminal-safe."""
    lines = [f"records: {stats.records}"]
    if stats.malformed:
        lines[0] += f" (skipped {stats.malformed} malformed lines)"
    lines += _section("decisions", stats.decisions.most_common())
    lines += _section("rules", stats.rules.most_common())
    lines += _section(f"top {TOP_TOOLS} tools", stats.tools.most_common(TOP_TOOLS))
    return "\n".join(lines)
