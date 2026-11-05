import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from cc_firewall.install import install

SRC = str(Path(__file__).resolve().parents[1] / "src")
EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.json"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    return tmp_path / "fw-home"


def run_cli(
    home: Path, *args: str, stdin: str = "", extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC, "CC_FIREWALL_HOME": str(home), **(extra_env or {})}
    return subprocess.run(
        [sys.executable, "-m", "cc_firewall", *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def payload(tool: str, tool_input: dict[str, Any]) -> str:
    return json.dumps(
        {
            "session_id": "s1",
            "cwd": "/work",
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
        }
    )


def write_policy(tmp_path: Path, **data: Any) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def records(home: Path) -> list[dict[str, Any]]:
    lines = (home / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_hook_denies_with_example_policy_and_logs(home: Path) -> None:
    result = run_cli(
        home,
        "hook",
        "--policy",
        str(EXAMPLE),
        stdin=payload("Read", {"file_path": "/proj/.env"}),
    )
    assert result.returncode == 0
    out = json.loads(result.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    assert "no-env-file" in out["permissionDecisionReason"]
    record = records(home)[0]
    assert (record["decision"], record["rules"], record["tool"]) == (
        "deny",
        ["no-env-file"],
        "Read",
    )


@pytest.mark.parametrize(
    ("tool", "tool_input", "decision"),
    [
        ("Read", {"file_path": "/proj/.env.example"}, None),
        ("Bash", {"command": "git push origin main"}, "ask"),
        ("Bash", {"command": "rm -rf build"}, "ask"),
        ("Bash", {"command": "ls"}, None),
    ],
)
def test_example_policy_decisions(
    home: Path, tool: str, tool_input: dict[str, Any], decision: str | None
) -> None:
    result = run_cli(home, "hook", "--policy", str(EXAMPLE), stdin=payload(tool, tool_input))
    assert result.returncode == 0
    if decision is None:
        assert result.stdout == ""
    else:
        assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == decision


def test_audit_mode_logs_but_outputs_nothing(home: Path, tmp_path: Path) -> None:
    rule = {"id": "r", "tools": ["Bash"], "field": "command", "regex": "boom"}
    policy = write_policy(
        tmp_path, mode="audit", rules=[{**rule, "decision": "deny", "reason": "no"}]
    )
    result = run_cli(
        home, "hook", "--policy", str(policy), stdin=payload("Bash", {"command": "boom"})
    )
    assert (result.returncode, result.stdout) == (0, "")
    assert records(home)[0]["decision"] == "would-deny"


def test_log_allowed_false_skips_allow_records(home: Path, tmp_path: Path) -> None:
    policy = write_policy(tmp_path, log_allowed=False)
    run_cli(home, "hook", "--policy", str(policy), stdin=payload("Bash", {"command": "ls"}))
    assert not (home / "audit.jsonl").exists()


def test_invalid_policy_and_bad_payload_fail_closed(home: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    for policy, stdin in ((bad, payload("Bash", {"command": "ls"})), (EXAMPLE, "garbage")):
        result = run_cli(home, "hook", "--policy", str(policy), stdin=stdin)
        assert result.returncode == 0
        out = json.loads(result.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny"
        assert out["permissionDecisionReason"].startswith("cc-firewall:")


def test_explicit_missing_policy_denies(home: Path, tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    result = run_cli(
        home, "hook", "--policy", str(missing), stdin=payload("Bash", {"command": "ls"})
    )
    out = json.loads(result.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert "does not exist" in out["permissionDecisionReason"]


@pytest.mark.parametrize(
    ("policy_text", "expected"), [("{}", "ok"), (None, "missing"), ("[", "invalid")]
)
def test_record_names_policy_state(
    home: Path, tmp_path: Path, policy_text: str | None, expected: str
) -> None:
    args: list[str] = []
    if policy_text is not None:
        (tmp_path / "p.json").write_text(policy_text, encoding="utf-8")
        args = ["--policy", str(tmp_path / "p.json")]
    empty_home = {"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}  # no default policy
    run_cli(home, "hook", *args, stdin=payload("Bash", {"command": "ls"}), extra_env=empty_home)
    assert records(home)[0]["policy"] == expected


def test_deadline_denies_when_stdin_stalls(home: Path) -> None:
    env = {**os.environ, "PYTHONPATH": SRC, "CC_FIREWALL_HOME": str(home)}
    env["CC_FIREWALL_DEADLINE"] = "0.5"
    proc = subprocess.Popen(
        [sys.executable, "-m", "cc_firewall", "hook", "--policy", str(EXAMPLE)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env=env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(b'{"tool_name": "Bash"')  # never closed: the read blocks
    proc.stdin.flush()
    try:
        assert proc.wait(timeout=10) == 0
        out = json.loads(proc.stdout.read())["hookSpecificOutput"]
    finally:
        proc.stdin.close()
        proc.kill()
    assert out["permissionDecision"] == "deny"
    assert "exceeded deadline" in out["permissionDecisionReason"]
    record = records(home)[0]
    assert (record["decision"], record["policy"], record["input"]) == ("deny", "ok", "")


def test_backtracking_regex_is_stopped_by_watchdog(home: Path, tmp_path: Path) -> None:
    rule = {"id": "redos", "tools": ["Bash"], "field": "command", "regex": "^(a+)+$"}
    policy = write_policy(tmp_path, rules=[{**rule, "decision": "deny", "reason": "x"}])
    start = time.monotonic()
    result = run_cli(
        home,
        "hook",
        "--policy",
        str(policy),
        stdin=payload("Bash", {"command": "a" * 40 + "!"}),
        extra_env={"CC_FIREWALL_DEADLINE": "0.5"},
    )
    # Exit 1 from faulthandler; the installed "|| exit 2" makes Claude Code block the call.
    assert result.returncode == 1
    assert "Timeout" in result.stderr
    assert time.monotonic() - start < 10


def test_installed_command_ignores_modules_planted_in_cwd(home: Path, tmp_path: Path) -> None:
    rule = {"id": "all", "tools": ["*"], "field": "*", "regex": ".", "decision": "deny"}
    policy = write_policy(tmp_path, rules=[{**rule, "reason": "deny all"}])
    project = tmp_path / "project"
    (project / "cc_firewall").mkdir(parents=True)
    (project / "cc_firewall" / "__init__.py").write_text("", encoding="utf-8")
    (project / "cc_firewall" / "__main__.py").write_text("raise SystemExit(0)", encoding="utf-8")
    settings = tmp_path / "settings.json"
    install(settings, policy=policy, dry_run=False)
    entry = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]
    argv = shlex.split(entry["hooks"][0]["command"])
    argv = argv[: argv.index("||")]
    result = subprocess.run(
        argv,
        input=payload("Bash", {"command": "ls"}),
        capture_output=True,
        text=True,
        cwd=project,
        env={**os.environ, "CC_FIREWALL_HOME": str(home)},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_audit_input_is_redacted_and_truncated(home: Path, tmp_path: Path) -> None:
    env_secret = "hunter2-" + "value-" + "9f8e7d"
    github_token = "gh" + "p_" + "A1b2" * 9
    command = f"curl -H {env_secret} {github_token} " + "pad" * 1000
    policy = write_policy(tmp_path)
    run_cli(
        home,
        "hook",
        "--policy",
        str(policy),
        stdin=payload("Bash", {"command": command}),
        extra_env={"MY_API_TOKEN": env_secret},
    )
    record = records(home)[0]
    assert env_secret not in record["input"]
    assert github_token not in record["input"]
    assert "[REDACTED]" in record["input"]
    assert len(record["input"]) <= 2000


def test_log_command_filters_by_decision(home: Path) -> None:
    run_cli(home, "hook", "--policy", str(EXAMPLE), stdin=payload("Bash", {"command": "ls"}))
    run_cli(home, "hook", "--policy", str(EXAMPLE), stdin=payload("Bash", {"command": "git push"}))
    result = run_cli(home, "log", "--decision", "ask")
    lines = result.stdout.splitlines()
    assert [json.loads(line)["decision"] for line in lines] == ["ask"]


def test_check_and_validate(home: Path) -> None:
    denied = run_cli(
        home,
        "check",
        "--tool",
        "Read",
        "--input",
        '{"file_path": ".env"}',
        "--policy",
        str(EXAMPLE),
    )
    assert denied.returncode == 1
    assert "no-env-file" in denied.stdout
    allowed = run_cli(
        home, "check", "--tool", "Bash", "--input", '{"command": "ls"}', "--policy", str(EXAMPLE)
    )
    assert allowed.returncode == 0
    valid = run_cli(home, "validate", "--policy", str(EXAMPLE))
    assert valid.returncode == 0
    assert "5 rules" in valid.stdout
