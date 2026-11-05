"""Shared data types: policy, rules, verdicts and hook input."""

import re
from dataclasses import dataclass, field
from typing import Any

DECISIONS = ("deny", "ask")
MODES = ("enforce", "audit")


@dataclass(frozen=True)
class Rule:
    """One policy rule.

    Exactly one of ``glob`` and ``regex`` is set. A rule matches a string value when that
    matcher hits and neither ``unless_glob`` nor ``unless_regex`` hits.

    Attributes:
        id: Unique rule identifier, shown in reasons and in the audit log.
        tools: Tool names or fnmatch patterns (for example ``mcp__*``) the rule applies to.
        field: Key in ``tool_input`` to inspect, or ``"*"`` for every string value.
        decision: ``"deny"`` or ``"ask"``.
        reason: Human-readable explanation.
        glob: fnmatch pattern, case-insensitive, matched against slash-normalized text.
        regex: Pattern searched anywhere in the value.
        unless_glob: Exception glob; a value matching it is skipped.
        unless_regex: Exception regex; a value matching it is skipped.
    """

    id: str
    tools: tuple[str, ...]
    field: str
    decision: str
    reason: str
    glob: str | None = None
    regex: re.Pattern[str] | None = None
    unless_glob: str | None = None
    unless_regex: re.Pattern[str] | None = None


@dataclass(frozen=True)
class Policy:
    """User-level firewall policy.

    Attributes:
        mode: ``"enforce"`` emits decisions; ``"audit"`` only logs what would happen.
        log_allowed: Also write allowed calls to the audit log.
        rules: Rules in file order.
    """

    mode: str = "enforce"
    log_allowed: bool = True
    rules: tuple[Rule, ...] = field(default=())


@dataclass(frozen=True)
class Verdict:
    """Result of evaluating one tool call: allow, ask or deny."""

    decision: str = "allow"
    rules: tuple[str, ...] = field(default=())
    reason: str = ""


@dataclass(frozen=True)
class HookInput:
    """The parts of the Claude Code hook payload the firewall uses."""

    tool: str
    tool_input: dict[str, Any]
    session_id: str = ""
    cwd: str = ""
