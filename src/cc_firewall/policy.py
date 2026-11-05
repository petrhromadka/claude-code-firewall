"""Loading and validation of the user-level policy file.

Only the user-level file (``~/.claude/cc-firewall.json``) is ever read. Project-level policy
files are deliberately not supported, so a cloned repository cannot weaken the policy.
"""

import json
import re
from pathlib import Path
from typing import Any

from cc_firewall.models import DECISIONS, MODES, Policy, Rule

RULE_KEYS = frozenset(
    {"id", "tools", "field", "glob", "regex", "unless_glob", "unless_regex", "decision", "reason"}
)
POLICY_KEYS = frozenset({"mode", "log_allowed", "rules"})


class PolicyError(Exception):
    """The policy file is unreadable or invalid; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        """Store the list of problems and join them into the message."""
        super().__init__("; ".join(errors))
        self.errors = errors


def default_policy_path() -> Path:
    """Return the default user-level policy path."""
    return Path.home() / ".claude" / "cc-firewall.json"


def load_policy(path: Path | None = None) -> Policy:
    """Load and validate the policy. A missing file yields an empty policy.

    Raises:
        PolicyError: The file cannot be read, is not JSON, or fails validation.
    """
    path = path or default_policy_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Policy()
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError([f"cannot read {path}: {exc}"]) from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise PolicyError([f"{path}: invalid JSON: {exc}"]) from exc
    return parse_policy(data)


def parse_policy(data: object) -> Policy:
    """Validate decoded JSON and build a Policy.

    Raises:
        PolicyError: With every problem found.
    """
    if not isinstance(data, dict):
        raise PolicyError(["policy must be a JSON object"])
    errors: list[str] = []
    unknown = sorted(set(data) - POLICY_KEYS)
    if unknown:
        errors.append(f"unknown policy keys: {', '.join(unknown)}")
    mode = data.get("mode", "enforce")
    if mode not in MODES:
        errors.append(f"'mode' must be one of {', '.join(MODES)}")
    log_allowed = data.get("log_allowed", True)
    if not isinstance(log_allowed, bool):
        errors.append("'log_allowed' must be true or false")
    rules = _parse_rules(data.get("rules", []), errors)
    if errors:
        raise PolicyError(errors)
    return Policy(mode=mode, log_allowed=log_allowed, rules=rules)


def _parse_rules(raw: object, errors: list[str]) -> tuple[Rule, ...]:
    if not isinstance(raw, list):
        errors.append("'rules' must be a list")
        return ()
    rules = [_parse_rule(item, f"rules[{i}]", errors) for i, item in enumerate(raw)]
    parsed = tuple(r for r in rules if r is not None)
    seen: set[str] = set()
    for rule in parsed:
        if rule.id in seen:
            errors.append(f"duplicate rule id '{rule.id}'")
        seen.add(rule.id)
    return parsed


def _parse_rule(raw: object, where: str, errors: list[str]) -> Rule | None:
    if not isinstance(raw, dict):
        errors.append(f"{where}: rule must be an object")
        return None
    start = len(errors)
    unknown = sorted(set(raw) - RULE_KEYS)
    if unknown:
        errors.append(f"{where}: unknown keys: {', '.join(unknown)}")
    if isinstance(raw.get("id"), str):
        where = f"{where} ({raw['id']})"
    text = {key: _text(raw, key, where, errors) for key in ("id", "field", "reason", "decision")}
    if text["decision"] is not None and text["decision"] not in DECISIONS:
        errors.append(f"{where}: 'decision' must be one of {', '.join(DECISIONS)}")
    tools = _tools(raw, where, errors)
    glob = _text(raw, "glob", where, errors, required=False)
    regex = _regex(raw, "regex", where, errors)
    if (raw.get("glob") is None) == (raw.get("regex") is None):
        errors.append(f"{where}: set exactly one of 'glob' or 'regex'")
    unless_glob = _text(raw, "unless_glob", where, errors, required=False)
    unless_regex = _regex(raw, "unless_regex", where, errors)
    if len(errors) > start:
        return None
    return Rule(
        id=str(text["id"]),
        tools=tools,
        field=str(text["field"]),
        decision=str(text["decision"]),
        reason=str(text["reason"]),
        glob=glob,
        regex=regex,
        unless_glob=unless_glob,
        unless_regex=unless_regex,
    )


def _text(
    raw: dict[str, Any], key: str, where: str, errors: list[str], *, required: bool = True
) -> str | None:
    value = raw.get(key)
    if value is None:
        if required:
            errors.append(f"{where}: '{key}' is required")
        return None
    if not isinstance(value, str) or not value:
        errors.append(f"{where}: '{key}' must be a non-empty string")
        return None
    return value


def _regex(raw: dict[str, Any], key: str, where: str, errors: list[str]) -> re.Pattern[str] | None:
    text = _text(raw, key, where, errors, required=False)
    if text is None:
        return None
    try:
        return re.compile(text)
    except re.error as exc:
        errors.append(f"{where}: '{key}' is not a valid regex: {exc}")
        return None


def _tools(raw: dict[str, Any], where: str, errors: list[str]) -> tuple[str, ...]:
    tools = raw.get("tools")
    if not isinstance(tools, list) or not tools or not all(isinstance(t, str) for t in tools):
        errors.append(f"{where}: 'tools' must be a non-empty list of strings")
        return ()
    return tuple(tools)
