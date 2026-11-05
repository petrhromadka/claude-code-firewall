import json
from pathlib import Path

import pytest

from cc_firewall import cli
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
    assert "12 passed, 0 failed" in capsys.readouterr().out

    failing = tmp_path / "policy.json"
    case = {"tool": "Bash", "input": {"command": "git push"}, "expect": "deny"}
    failing.write_text(json.dumps({"rules": [RULE], "tests": [case]}), encoding="utf-8")
    assert main(["test", "--policy", str(failing)]) == 1
    assert "0 passed, 1 failed" in capsys.readouterr().out

    assert main(["test", "--policy", str(tmp_path / "missing.json")]) == 2
    assert capsys.readouterr().err.startswith("error: ")


def test_check_and_validate_explain_a_missing_policy_and_bad_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "cc-firewall.json"
    monkeypatch.setattr(cli, "default_policy_path", lambda: missing)
    assert main(["validate"]) == 2
    assert capsys.readouterr().err == (
        f"error: no policy at {missing}; copy examples/policy.json there (see README Quick start)\n"
    )
    assert main(["check", "--tool", "Bash", "--input", "{}"]) == 0
    assert f"note: no policy file at {missing}; every call is allowed" in capsys.readouterr().err

    check = ["check", "--policy", str(EXAMPLE), "--input"]
    assert main([*check, '{"command": "ls"}', "--tool", "bash"]) == 0
    assert capsys.readouterr().err == (
        "note: no rule applies to tool 'bash'; tool names are case-sensitive "
        "(did you mean 'Bash'?)\n"
    )
    assert main([*check, r'{"file_path": "C:\a"}', "--tool", "Read"]) == 2
    err = capsys.readouterr().err
    assert err.startswith(r"error: --input is not valid JSON: Invalid \escape")
    assert err.endswith(r". Write a backslash as \\ or use forward slashes" + "\n")


def test_check_and_validate_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "policy.json"
    slow = {**RULE, "id": "slow", "unless_regex": "(a+)+", "cwd_glob": "/work/**"}
    policy.write_text(json.dumps({"rules": [RULE, slow]}), encoding="utf-8")
    check = ["check", "--tool", "Bash", "--policy", str(policy), "--input"]
    assert main([*check, '{"command": "ls"}']) == 0
    assert main([*check, '{"command": "git push"}', "--cwd", "/work"]) == 1
    capsys.readouterr()

    assert main(["validate", "--policy", str(policy)]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("ok: 2 rules")
    assert "warning: rules[1] (slow): regex may be slow" in err

    missing = str(tmp_path / "missing.json")
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"rules": [{**RULE, "glob": None}]}), encoding="utf-8")
    for args in (
        ["validate", "--policy", missing],
        ["validate", "--policy", str(invalid)],
        [*check[:-3], "--policy", missing, "--input", "{}"],
        [*check, "[]"],
    ):
        assert main(args) == 2, args
        assert capsys.readouterr().err.startswith("error: ")
