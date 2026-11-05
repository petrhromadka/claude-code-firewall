import io
import json
from pathlib import Path
from typing import Any

import pytest

from cc_firewall.engine import evaluate
from cc_firewall.hook import run_hook
from cc_firewall.policy import (
    POLICY_KEYS,
    RULE_KEYS,
    TEST_KEYS,
    PolicyError,
    load_policy,
    parse_policy,
    slow_regex_warnings,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "policy.json"
SCHEMA = ROOT / "schema" / "policy.schema.json"


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
        (
            {"tools": ["Read"], "field": "file_path", "glob": "**/.env", "regex": None},
            "Read",
            {"file_path": "C:\\p\\.env."},
            "deny",
        ),
        (
            {"tools": ["Read"], "field": "file_path", "glob": "**/.env", "regex": None},
            "Read",
            {"file_path": "/p/.env::$DATA"},
            "deny",
        ),
        ({"tools": ["mcp__*"], "field": "*"}, "mcp__srv__tool", {"a": {"b": ["xx"]}}, "deny"),
        (
            {"tools": ["mcp__*"], "field": "*", "glob": "**/.env", "regex": None},
            "mcp__srv__tool",
            {"files": {"/p/.env": "read"}},
            "deny",
        ),
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
        {"rules": [rule("a", cwd_glob="")]},
        {"$schema": 1},
        {"tests": {}},
        {"tests": [{"tool": "Bash", "input": {}, "expect": "maybe"}]},
        {"tests": [{"tool": "Bash", "input": "x", "expect": "allow"}]},
        {"tests": [{"tool": "Bash", "input": {}, "expect": "allow", "name": "typo"}]},
    ],
)
def test_invalid_policy_raises(data: object) -> None:
    with pytest.raises(PolicyError):
        parse_policy(data)


@pytest.mark.parametrize(
    ("cwd", "expected"),
    [
        ("/home/me/work/app", "deny"),
        ("C:\\Home\\Me\\Work\\App", "deny"),
        ("/home/me/other", "allow"),
        (None, "allow"),
    ],
)
def test_cwd_glob_limits_rule_to_matching_directories(cwd: str | None, expected: str) -> None:
    policy = make_policy(rule("r", cwd_glob="**/work/**"))
    assert evaluate(policy, "Bash", {"command": "x"}, cwd=cwd).decision == expected


@pytest.mark.parametrize(
    ("cwd", "expected"),
    [
        ("/home/me/app", "deny"),
        ("/home/me/app/src/lib", "deny"),
        ("/home/me/appx", "allow"),
    ],
)
def test_trailing_double_star_matches_the_directory_itself(cwd: str, expected: str) -> None:
    policy = make_policy(rule("r", cwd_glob="/home/me/app/**"))
    assert evaluate(policy, "Bash", {"command": "x"}, cwd=cwd).decision == expected


def test_hook_passes_payload_cwd_to_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CC_FIREWALL_HOME", str(tmp_path / "home"))
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": [rule("r", cwd_glob="/work")]}), encoding="utf-8")

    def decide(cwd: str) -> str | None:
        data = {"tool_name": "Bash", "tool_input": {"command": "x"}, "cwd": cwd}
        return run_hook(io.BytesIO(json.dumps(data).encode()), path)

    assert '"deny"' in (decide("/work") or "")
    assert decide("/elsewhere") is None


@pytest.mark.parametrize(
    ("pattern", "slow"),
    [
        ("(a+)+", True),
        ("(a*)*", True),
        ("(.*)*", True),
        ("(?:\\w+\\s?)+$", True),
        ("(x{2,})+", True),
        ("(a\\+)+", False),
        ("(ab)+", False),
        ("^git push\\b", False),
    ],
)
def test_slow_regex_warning(pattern: str, slow: bool) -> None:
    policy = make_policy(rule("ok"), rule("r", regex=pattern), rule("u", unless_regex=pattern))
    expected = (
        [
            "rules[1] (r): regex may be slow on some inputs",
            "rules[2] (u): regex may be slow on some inputs",
        ]
        if slow
        else []
    )
    assert slow_regex_warnings(policy) == expected


def test_example_policy_has_no_slow_regex_warnings() -> None:
    assert slow_regex_warnings(load_policy(EXAMPLE, required=True)) == []


def test_schema_lists_exactly_the_keys_the_validator_accepts() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    defs = schema["$defs"]
    assert set(schema["properties"]) == POLICY_KEYS
    assert set(defs["rule"]["properties"]) == RULE_KEYS
    assert set(defs["test"]["properties"]) == TEST_KEYS
    for node in (schema, defs["rule"], defs["test"]):
        assert node["additionalProperties"] is False


_WRONG_TYPE = {"string": 1, "array": "x", "object": "x"}
_TEST_CASE = {"tool": "Bash", "input": {}, "expect": "allow"}


@pytest.mark.parametrize(
    ("kind", "key"),
    [("rule", k) for k in sorted(RULE_KEYS)] + [("test", k) for k in sorted(TEST_KEYS)],
)
def test_validator_rejects_the_values_the_schema_rejects(kind: str, key: str) -> None:
    defs = json.loads(SCHEMA.read_text(encoding="utf-8"))["$defs"]
    prop = defs[kind]["properties"][key]
    if "$ref" in prop:
        prop = defs[prop["$ref"].rsplit("/", 1)[1]]
    base = rule("a") if kind == "rule" else dict(_TEST_CASE)
    if key == "glob":
        del base["regex"]
    wrap = "rules" if kind == "rule" else "tests"
    wrong = _WRONG_TYPE.get(prop.get("type"), "not-in-enum")
    for value in (None, wrong):
        with pytest.raises(PolicyError):
            parse_policy({wrap: [{**base, key: value}]})
    if prop.get("type") == "string":
        parse_policy({wrap: [{**base, key: "r.*"}]})


def test_unless_glob_trailing_globstar_does_not_exempt_bare_dir() -> None:
    policy = parse_policy(
        {
            "rules": [
                {
                    "id": "r",
                    "tools": ["Read"],
                    "field": "file_path",
                    "glob": "/srv/**",
                    "unless_glob": "/srv/public/**",
                    "decision": "deny",
                    "reason": "x",
                }
            ]
        }
    )
    assert evaluate(policy, "Read", {"file_path": "/srv/public"}).decision == "deny"
    assert evaluate(policy, "Read", {"file_path": "/srv/public/a.txt"}).decision == "allow"
