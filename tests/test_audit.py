import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from cc_firewall import audit
from cc_firewall.models import HookInput
from cc_firewall.sensitive import secret_values


@pytest.fixture
def log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CC_FIREWALL_HOME", str(tmp_path / "fw-home"))
    return tmp_path / "fw-home" / "audit.jsonl"


def write(tool_input: dict[str, Any], cwd: str = "/work") -> None:
    audit.log_decision(HookInput("Bash", tool_input, "s1", cwd), "deny", ("r1",), "ok")


def last_record(log: Path) -> dict[str, Any]:
    return json.loads(log.read_text(encoding="utf-8").splitlines()[-1])


@pytest.mark.parametrize("special", ['"', "\\", "\n", "\t"])
def test_env_secret_with_escaped_chars_never_logged(
    log: Path, monkeypatch: pytest.MonkeyPatch, special: str
) -> None:
    secret = "s3cr" + special + "et-" + "value-9f8e"
    monkeypatch.setenv("OPENAI_KEY", secret)
    write({"command": f"echo {secret}", secret: "as key"}, cwd=f"/home/{secret}")
    raw = log.read_bytes()
    escaped = json.dumps(secret, ensure_ascii=False)[1:-1]
    assert secret.encode() not in raw
    assert escaped.encode() not in raw
    record = last_record(log)
    assert secret not in record["input"]
    assert secret not in record["cwd"]
    assert "[REDACTED]" in record["input"]


def test_numeric_env_secret_redacted_in_numbers(log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BANK_PIN_SECRET", "73019284")
    write({"pin": 73019284, "nested": [{"id": 1.5, "acct": 9973019284}], "ok": 42, "b": True})
    record = last_record(log)
    assert "73019284" not in record["input"]
    assert json.loads(record["input"]) == {
        "pin": "[REDACTED]",
        "nested": [{"id": 1.5, "acct": "99[REDACTED]"}],
        "ok": 42,
        "b": True,
    }


def test_private_key_body_redacted(log: Path) -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "Zm9vYmFy" * 4
    kind = "RSA " + "PRIVATE KEY"
    pem = f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"
    write({"content": f"before {pem} after", "truncated": f"-----BEGIN {kind}-----\n{body}"})
    record = last_record(log)
    assert body not in record["input"]
    assert "before [REDACTED] after" in record["input"]


def test_lone_surrogate_input_still_written(log: Path) -> None:
    write({"command": "echo \ud800"})
    assert last_record(log)["decision"] == "deny"


def test_rotation_keeps_three_generations(log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 10)
    for n in range(5):
        write({"command": f"run {n}"})
    names = sorted(p.name for p in log.parent.iterdir())
    assert names == ["audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"]
    assert "run 4" in log.read_text(encoding="utf-8")
    assert "run 1" in (log.parent / "audit.jsonl.3").read_text(encoding="utf-8")


def test_rotation_lock_held_skips_rotation_but_keeps_record(
    log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 10)
    write({"command": "first"})
    lock = log.parent / "audit.lock"
    lock.touch()
    write({"command": "while locked"})
    assert sorted(p.name for p in log.parent.iterdir()) == ["audit.jsonl", "audit.lock"]
    assert "while locked" in log.read_text(encoding="utf-8")
    old = time.time() - 2 * audit.STALE_LOCK_SECONDS
    os.utime(lock, (old, old))
    write({"command": "after stale"})
    assert sorted(p.name for p in log.parent.iterdir()) == ["audit.jsonl", "audit.jsonl.1"]
    assert "after stale" in log.read_text(encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_log_file_and_dir_are_private(log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 10)
    log.parent.mkdir(mode=0o700)
    log.touch(mode=0o644)
    log.chmod(0o644)  # a pre-existing log with looser permissions is tightened
    write({"command": "ls"})
    write({"command": "ls"})
    assert stat.S_IMODE(log.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE((log.parent / "audit.jsonl.1").stat().st_mode) == 0o600


def test_control_chars_written_as_ascii_escapes(log: Path) -> None:
    command = "a\x1b[2Jb\x9bc\u202ed"
    write({"command": command})
    assert log.read_bytes().isascii()
    assert json.loads(last_record(log)["input"]) == {"command": command}


def test_dict_keys_tool_and_session_redacted_and_kept_apart(
    log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = "key-" + "value-1a2b3c", "pass-" + "value-4d5e6f"
    monkeypatch.setenv("OPENAI_KEY", first)
    monkeypatch.setenv("DB_PASS", second)
    tool_input = {first: 1, second: 2, "[REDACTED]": 3, "plain": f"x {first} y"}
    audit.log_decision(HookInput(f"mcp__{first}", tool_input, second, "/w"), "deny", (), "ok")
    record = last_record(log)
    assert json.loads(record["input"]) == {
        "[REDACTED]": 1,
        "[REDACTED]#2": 2,
        "[REDACTED]#3": 3,
        "plain": "x [REDACTED] y",
    }
    assert (record["tool"], record["session_id"]) == ("mcp__[REDACTED]", "[REDACTED]")


def test_overlapping_secrets_longer_redacted_whole(
    log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    short = "abcd1234" + "efgh"
    monkeypatch.setenv("SHORT_TOKEN", short)
    monkeypatch.setenv("LONG_TOKEN", short + "5678ijkl")
    write({"a": f"x {short}5678ijkl y", "b": f"x {short} y"})
    assert json.loads(last_record(log)["input"]) == {"a": "x [REDACTED] y", "b": "x [REDACTED] y"}


@pytest.mark.parametrize(
    "token",
    [
        "gh" + "o_" + "A1b2" * 9,
        "gh" + "s_" + "A1b2" * 9,
        "github" + "_pat_" + "A1b2_" * 13,
        "sk-" + "ant-" + "api03-" + "A1b2" * 6,
        "sk-" + "proj-" + "A1b2" * 9,
        "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "xo" + "xb-" + "1234567890-abcdef",
        "AI" + "za" + "A1b2" * 8 + "xyz",
        "gl" + "pat-" + "A1b2" * 6,
        "np" + "m_" + "A1b2" * 9,
    ],
)
def test_known_token_formats_redacted(log: Path, token: str) -> None:
    write({"command": f"use {token} now"})
    assert json.loads(last_record(log)["input"]) == {"command": "use [REDACTED] now"}


def test_password_style_names_are_secret_but_cwd_vars_are_not() -> None:
    env = {
        "DB_PASS": "value-pass-1",
        "MYSQL_PWD": "value-pwd-22",
        "SMTP_PW": "value-pw-333",
        "PWD": "/home/me/project",
        "OldPwd": "/home/me/other",
        "PATH": "/usr/bin:/bin",
    }
    assert sorted(secret_values(env)) == ["value-pass-1", "value-pw-333", "value-pwd-22"]


@pytest.mark.parametrize("kind", ["future", "directory"])
def test_future_or_directory_lock_is_stale(
    log: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 10)
    write({"command": "first"})
    lock = log.parent / "audit.lock"
    if kind == "directory":
        lock.mkdir()
    else:
        lock.touch()
        future = time.time() + 60
        os.utime(lock, (future, future))
    write({"command": "second"})
    assert sorted(p.name for p in log.parent.iterdir()) == ["audit.jsonl", "audit.jsonl.1"]


def test_rotate_skipped_when_file_already_small_under_lock(log: Path) -> None:
    write({"command": "small"})
    audit._rotate_locked(log)  # the size check outside the lock saw a big file; it shrank
    assert sorted(p.name for p in log.parent.iterdir()) == ["audit.jsonl"]


def test_takeover_puts_back_a_live_lock_it_moved(
    log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log.parent.mkdir()
    lock = log.parent / "audit.lock"
    lock.write_text("other-hook", encoding="ascii")
    verdicts = iter([True, False])  # stale when checked, live once moved: another hook won
    monkeypatch.setattr(audit, "_is_stale", lambda _: next(verdicts))
    assert not audit._acquire(lock, "mine")
    assert sorted(p.name for p in log.parent.iterdir()) == ["audit.lock"]
    assert lock.read_text(encoding="ascii") == "other-hook"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks and O_NOFOLLOW")
def test_symlinked_log_is_not_followed(log: Path, tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("keep", encoding="utf-8")
    log.parent.mkdir()
    log.symlink_to(target)
    write({"command": "ls"})
    assert target.read_text(encoding="utf-8") == "keep"
