import json
import os
import shlex
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from cc_firewall.doctor import doctor
from cc_firewall.install import hook_entry, install


@pytest.fixture(autouse=True)
def _audit_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CC_FIREWALL_HOME", str(tmp_path / "fw-home"))


def _statuses(report: str) -> dict[str, str]:
    """Map each check to OK or FAIL; WARN and NOTE lines are left out."""
    lines = [line.split() for line in report.splitlines() if line[:4] in ("OK  ", "FAIL")]
    return {words[1].rstrip(":"): words[0] for words in lines}


def _write_policy(path: Path, regex: str = "^rm ") -> Path:
    rule = {"id": "r", "tools": ["Bash"], "field": "command", "regex": regex}
    path.write_text(json.dumps({"rules": [{**rule, "decision": "deny", "reason": "no"}]}))
    return path


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


def _slow_timeout(policy: Path, marker: Path) -> dict[str, object]:
    entry = {**hook_entry(policy), "timeout": 600}
    del entry["onFailure"]
    return entry


def _foreign_code(policy: Path, marker: Path) -> dict[str, object]:
    touch = f"import pathlib; pathlib.Path({str(marker)!r}).touch()"
    argv = [sys.executable, "-c", touch, "-m", "cc_firewall", "hook", "--policy", str(policy)]
    return {**hook_entry(policy), "command": shlex.join(argv) + " || exit 2"}


def _bare_interpreter(policy: Path, marker: Path) -> dict[str, object]:
    name = Path(sys.executable).name
    args = ["-I", "-m", "cc_firewall", "hook", "--policy", str(policy)]
    return {"type": "command", "command": name, "args": args}


@pytest.mark.parametrize("make", [_slow_timeout, _foreign_code, _bare_interpreter])
def test_doctor_flags_stale_entry_without_running_its_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make: Callable[[Path, Path], dict]
) -> None:
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent), prepend=os.pathsep)
    settings = tmp_path / "settings.json"
    policy = _write_policy(tmp_path / "policy.json")
    marker = tmp_path / "marker"
    entry = {"hooks": [make(policy, marker)]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [entry]}}), encoding="utf-8")

    report, code = doctor(settings, policy)
    assert code == 1
    assert _statuses(report) == {
        "settings": "OK",
        "hook": "FAIL",
        "interpreter": "OK",
        "self-test": "OK",
        "policy": "OK",
        "audit": "OK",
    }, report
    assert not marker.exists()


def test_doctor_policy_option_checks_that_file_and_warns_on_slow_regex(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    installed = _write_policy(tmp_path / "policy.json")
    install(settings, policy=installed, dry_run=False, run_self_test=False)
    other = _write_policy(tmp_path / "other.json", regex="(a+)+$")

    report, code = doctor(settings, other)
    assert code == 0, report
    assert set(_statuses(report).values()) == {"OK"}
    assert f"NOTE policy: checking {other}, but the installed hook reads {installed}" in report
    assert "WARN policy: rules[0] (r): regex may be slow on some inputs" in report
    assert f"OK   policy: {other}: 1 rules" in report
