import json
import stat
import sys
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
    audit.log_decision(HookInput("Bash", tool_input, "s1", cwd), "deny", ("r1",))


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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_log_file_and_dir_are_private(log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit, "MAX_LOG_BYTES", 10)
    write({"command": "ls"})
    write({"command": "ls"})
    assert stat.S_IMODE(log.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE((log.parent / "audit.jsonl.1").stat().st_mode) == 0o600
