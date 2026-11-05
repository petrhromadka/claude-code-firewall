import json
from pathlib import Path

import pytest

from cc_firewall.cli import main
from cc_firewall.policy import parse_policy
from cc_firewall.policytest import run_tests

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.json"

RULE = {
    "id": "push",
    "tools": ["Bash"],
    "field": "command",
    "regex": "git push",
    "cwd_glob": "/work/**",
    "decision": "ask",
    "reason": "push",
}


def test_cases_pass_or_fail_against_the_rules_and_cwd() -> None:
    policy = parse_policy(
        {
            "mode": "audit",
            "rules": [RULE],
            "tests": [
                {
                    "tool": "Bash",
                    "input": {"command": "git push"},
                    "cwd": "/work/a",
                    "expect": "ask",
                },
                {"tool": "Bash", "input": {"command": "git push"}, "expect": "allow"},
                {"tool": "Bash", "input": {"command": "ls"}, "cwd": "/work/a", "expect": "deny"},
            ],
        }
    )
    results = run_tests(policy)
    assert [r.passed for r in results] == [True, True, False]
    assert results[0].describe().startswith("PASS tests[0] Bash")
    assert "(rules: push)" in results[0].describe()
    assert "FAIL tests[2]" in results[2].describe()
    assert "expected deny, got allow" in results[2].describe()


def test_cli_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test", "--policy", str(EXAMPLE)]) == 0
    assert "10 passed, 0 failed" in capsys.readouterr().out

    failing = tmp_path / "policy.json"
    case = {"tool": "Bash", "input": {"command": "git push"}, "expect": "deny"}
    failing.write_text(json.dumps({"rules": [RULE], "tests": [case]}), encoding="utf-8")
    assert main(["test", "--policy", str(failing)]) == 1
    assert "0 passed, 1 failed" in capsys.readouterr().out

    assert main(["test", "--policy", str(tmp_path / "missing.json")]) == 2
