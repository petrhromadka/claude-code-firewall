import json
from pathlib import Path

import pytest

from cc_firewall.cli import main


def record(ts: str, tool: str, decision: str, *rules: str) -> str:
    data = {"ts": ts, "tool": tool, "decision": decision, "rules": list(rules), "input": "{}"}
    return json.dumps(data)


@pytest.fixture
def log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CC_FIREWALL_HOME", str(tmp_path))
    rotated = [record("2026-10-01T10:00:00Z", "Read", "deny", "no-env")]
    current = [
        record("2026-11-01T10:00:00Z", "Bash", "ask", "push"),
        "not json",
        '{"ts": "2026-11-01T10:00:00Z"}',
        record("2026-11-02T10:00:00Z", "Bash", "deny", "push", "no-env"),
        record("2026-11-03T10:00:00Z", "Grep", "allow"),
    ]
    (tmp_path / "audit.jsonl.1").write_text("\n".join(rotated) + "\n", encoding="utf-8")
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(current) + "\n", encoding="utf-8")
    return path


def test_stats_counts_and_since(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["stats"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "records: 4 (skipped 2 malformed lines)"
    assert "  no-env  2" in out
    assert "  push    2" in out
    assert "  deny   2" in out
    assert "  Bash  2" in out

    assert main(["stats", "--since", "2026-11-02"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("records: 2 ")
    assert "Read" not in out


def test_log_filters_by_rule(log: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["log", "--rule", "push", "--decision", "deny"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line)["ts"][:10] for line in lines] == ["2026-11-02"]
    assert main(["log", "--rule", "push", "--tail", "1"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1
