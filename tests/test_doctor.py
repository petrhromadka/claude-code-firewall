import json
from pathlib import Path

import pytest

from cc_firewall.doctor import doctor
from cc_firewall.install import install


@pytest.fixture(autouse=True)
def _audit_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CC_FIREWALL_HOME", str(tmp_path / "fw-home"))


def _statuses(report: str) -> dict[str, str]:
    lines = [line.split() for line in report.splitlines() if not line.startswith(" ")]
    return {words[1].rstrip(":"): words[0] for words in lines}


def test_doctor_passes_after_install(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    policy.write_text('{"rules": []}', encoding="utf-8")
    install(settings, policy=policy, dry_run=False, run_self_test=False)

    report, code = doctor(settings)
    assert code == 0, report
    assert set(_statuses(report).values()) == {"OK"}
    assert len(_statuses(report)) == 6


def test_doctor_fails_on_broken_install(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    bad_policy = tmp_path / "bad.json"
    bad_policy.write_text('{"mode": "loud"}', encoding="utf-8")
    command = f"'{tmp_path / 'gone' / 'python'}' -I -m cc_firewall hook --policy '{bad_policy}'"
    stale = {"type": "command", "command": command + " || exit 2"}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [stale]}]}}))

    report, code = doctor(settings)
    assert code == 1
    assert _statuses(report) == {
        "settings": "OK",
        "hook": "FAIL",
        "interpreter": "FAIL",
        "self-test": "FAIL",
        "policy": "FAIL",
        "audit": "OK",
    }

    settings.write_text("{not json", encoding="utf-8")
    report, code = doctor(settings, bad_policy)
    assert code == 1
    assert _statuses(report)["settings"] == "FAIL"
