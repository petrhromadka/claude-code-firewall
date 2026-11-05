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
