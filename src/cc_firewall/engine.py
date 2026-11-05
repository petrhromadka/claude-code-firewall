"""Rule matching: decide allow, ask or deny for one tool call."""

import re
from collections.abc import Iterator
from fnmatch import fnmatchcase
from typing import Any

from cc_firewall.models import Policy, Rule, Verdict


def glob_match(pattern: str, value: str) -> bool:
    """Match value against an fnmatch pattern, ignoring case and path separator style.

    ``**/`` also matches zero directories, so ``**/.env`` matches a bare ``.env``.
    """
    pattern = pattern.replace("\\", "/").lower()
    value = value.replace("\\", "/").lower()
    return any(fnmatchcase(value, p) for p in {pattern, pattern.replace("**/", "")})


def _walk_strings(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for child in node.values():
            yield from _walk_strings(child)
    elif isinstance(node, list):
        for child in node:
            yield from _walk_strings(child)


def _values(rule: Rule, tool_input: dict[str, Any]) -> Iterator[str]:
    if rule.field == "*":
        yield from _walk_strings(tool_input)
        return
    value = tool_input.get(rule.field)
    if isinstance(value, str):
        yield value


def _hit(glob: str | None, regex: re.Pattern[str] | None, value: str) -> bool:
    if glob is not None and glob_match(glob, value):
        return True
    return regex is not None and regex.search(value) is not None


def _value_matches(rule: Rule, value: str) -> bool:
    if not _hit(rule.glob, rule.regex, value):
        return False
    return not _hit(rule.unless_glob, rule.unless_regex, value)


def rule_matches(rule: Rule, tool: str, tool_input: dict[str, Any]) -> bool:
    """Return True if the rule applies to this tool call."""
    if not any(fnmatchcase(tool, pattern) for pattern in rule.tools):
        return False
    return any(_value_matches(rule, v) for v in _values(rule, tool_input))


def evaluate(policy: Policy, tool: str, tool_input: dict[str, Any]) -> Verdict:
    """Evaluate all rules; deny beats ask, and the reason names every matched rule."""
    matched = [r for r in policy.rules if rule_matches(r, tool, tool_input)]
    if not matched:
        return Verdict()
    decision = "deny" if any(r.decision == "deny" for r in matched) else "ask"
    detail = "; ".join(f"[{r.id}] {r.reason}" for r in matched)
    return Verdict(decision, tuple(r.id for r in matched), f"cc-firewall: {detail}")
