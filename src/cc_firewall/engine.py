"""Rule matching: decide allow, ask or deny for one tool call."""

import re
from collections.abc import Iterator
from fnmatch import fnmatchcase
from typing import Any

from cc_firewall.models import Policy, Rule, Verdict

_STREAM = re.compile(r"(?<=[^/:]):[^/]*$")


def normalize_path(value: str) -> str:
    """Normalize a path the way Windows resolves it, so aliases of one file compare equal.

    Lowercases, uses ``/`` as the separator, drops an NTFS stream suffix (``.env::$DATA``)
    and strips trailing dots and spaces from each component (``.env.`` opens ``.env``).
    """
    value = _STREAM.sub("", value.replace("\\", "/").lower())
    return "/".join(part.rstrip(". ") or part for part in value.split("/"))


def glob_match(pattern: str, value: str) -> bool:
    """Match value against an fnmatch pattern after normalizing both as paths.

    ``**/`` also matches zero directories, so ``**/.env`` matches a bare ``.env``.
    """
    pattern = pattern.replace("\\", "/").lower()
    value = normalize_path(value)
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


def rule_matches(rule: Rule, tool: str, tool_input: dict[str, Any], cwd: str | None = None) -> bool:
    """Return True if the rule applies to this tool call.

    A rule with ``cwd_glob`` applies only when ``cwd`` is given and matches it.
    """
    if not any(fnmatchcase(tool, pattern) for pattern in rule.tools):
        return False
    if rule.cwd_glob is not None and (cwd is None or not glob_match(rule.cwd_glob, cwd)):
        return False
    return any(_value_matches(rule, v) for v in _values(rule, tool_input))


def evaluate(
    policy: Policy, tool: str, tool_input: dict[str, Any], *, cwd: str | None = None
) -> Verdict:
    """Evaluate all rules; deny beats ask, and the reason names every matched rule.

    ``cwd`` is the session's working directory; without it, rules with ``cwd_glob`` never match.
    """
    matched = [r for r in policy.rules if rule_matches(r, tool, tool_input, cwd)]
    if not matched:
        return Verdict()
    decision = "deny" if any(r.decision == "deny" for r in matched) else "ask"
    detail = "; ".join(f"[{r.id}] {r.reason}" for r in matched)
    return Verdict(decision, tuple(r.id for r in matched), f"cc-firewall: {detail}")
