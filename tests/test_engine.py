from typing import Any

import pytest

from cc_firewall.engine import evaluate
from cc_firewall.policy import PolicyError, parse_policy


def make_policy(*rules: dict[str, Any], **top: Any):
    return parse_policy({"rules": list(rules), **top})


def rule(rule_id: str, **overrides: Any) -> dict[str, Any]:
    base = {
        "id": rule_id,
        "tools": ["Bash"],
        "field": "command",
        "regex": "x",
        "decision": "deny",
        "reason": f"reason {rule_id}",
    }
    return {**base, **overrides}


@pytest.mark.parametrize(
    ("overrides", "tool", "tool_input", "expected"),
    [
        ({"regex": "^git push\\b"}, "Bash", {"command": "git push origin"}, "deny"),
        ({"regex": "^git push\\b"}, "Bash", {"command": "echo git push"}, "allow"),
        ({"regex": "^git push\\b"}, "Read", {"command": "git push"}, "allow"),
        ({"regex": "x", "field": "other"}, "Bash", {"command": "x"}, "allow"),
        (
            {"tools": ["Read"], "field": "file_path", "glob": "**/.env", "regex": None},
            "Read",
            {"file_path": "C:\\Proj\\Sub\\.ENV"},
            "deny",
        ),
        (
            {"tools": ["Read"], "field": "file_path", "glob": "**/.env", "regex": None},
            "Read",
            {"file_path": ".env"},
            "deny",
        ),
        (
            {"tools": ["Read"], "field": "file_path", "glob": "**/.env", "regex": None},
            "Read",
            {"file_path": "/a/.env.example"},
            "allow",
        ),
        ({"tools": ["mcp__*"], "field": "*"}, "mcp__srv__tool", {"a": {"b": ["xx"]}}, "deny"),
        ({"tools": ["mcp__*"], "field": "*"}, "Bash", {"a": "xx"}, "allow"),
        ({"unless_regex": "dry"}, "Bash", {"command": "x dry"}, "allow"),
        ({"unless_glob": "*dry*"}, "Bash", {"command": "x dry"}, "allow"),
        ({"unless_regex": "dry"}, "Bash", {"command": "x wet"}, "deny"),
    ],
)
def test_rule_matching(
    overrides: dict[str, Any], tool: str, tool_input: dict[str, Any], expected: str
) -> None:
    raw = {k: v for k, v in rule("r", **overrides).items() if v is not None}
    assert evaluate(make_policy(raw), tool, tool_input).decision == expected


def test_deny_beats_ask_and_reason_lists_every_rule() -> None:
    policy = make_policy(
        rule("asker", decision="ask"), rule("denier"), rule("other-ask", decision="ask")
    )
    verdict = evaluate(policy, "Bash", {"command": "x"})
    assert verdict.decision == "deny"
    assert verdict.rules == ("asker", "denier", "other-ask")
    for rule_id in verdict.rules:
        assert f"[{rule_id}]" in verdict.reason


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"mode": "bogus"},
        {"rules": [rule("a", glob="*")]},
        {"rules": [{k: v for k, v in rule("a").items() if k != "regex"}]},
        {"rules": [rule("a", regex="(")]},
        {"rules": [rule("a", decision="allow")]},
        {"rules": [rule("a"), rule("a")]},
        {"rules": [rule("a", typo=1)]},
    ],
)
def test_invalid_policy_raises(data: object) -> None:
    with pytest.raises(PolicyError):
        parse_policy(data)
