import json
import shutil
import sys
from pathlib import Path

import pytest

from cc_firewall.install import SelfTestError, hook_argv, hook_entry, install, uninstall


def test_install_is_idempotent_and_preserves_settings(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    existing = {
        "model": "opus",
        "env": {"API_TOKEN": "secret-value"},
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "bye"}]}],
        },
    }
    raw = "\ufeff" + json.dumps(existing)
    settings.write_text(raw, encoding="utf-8")

    dry = install(settings, policy=policy, dry_run=True)
    assert "secret-value" not in dry
    assert len(json.loads(dry)["hooks"]["PreToolUse"]) == 2
    assert settings.read_text(encoding="utf-8") == raw

    install(settings, policy=policy, dry_run=False, run_self_test=False)
    first = settings.read_text(encoding="utf-8")
    assert settings.with_name("settings.json.bak").read_text(encoding="utf-8") == raw
    data = json.loads(first)
    assert {k: data[k] for k in ("model", "env")} == {"model": "opus", "env": existing["env"]}
    assert data["hooks"]["Stop"] == existing["hooks"]["Stop"]
    entries = data["hooks"]["PreToolUse"]
    assert entries == [
        existing["hooks"]["PreToolUse"][0],
        {"matcher": "*", "hooks": [hook_entry(policy)]},
    ]
    assert entries[1]["hooks"][0]["shell"] == "bash"

    assert install(settings, policy=policy, dry_run=False).startswith("already installed")
    assert settings.read_text(encoding="utf-8") == first


@pytest.mark.parametrize(
    "stale",
    [
        {"type": "command", "command": '"/old/python" -m cc_firewall hook || exit 2'},
        {"type": "command", "command": "/old/python", "args": ["-m", "cc_firewall", "hook"]},
    ],
)
def test_install_upgrades_stale_entry_in_place(tmp_path: Path, stale: dict[str, object]) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    mine = {"type": "command", "command": "mine"}
    entry = {"matcher": "Bash|Read", "hooks": [mine, stale]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [entry]}}), encoding="utf-8")

    result = install(settings, policy=policy, dry_run=False, run_self_test=False)
    assert result.startswith("installed")
    entries = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert entries == [{"matcher": "Bash|Read", "hooks": [mine, hook_entry(policy)]}]


def test_install_creates_missing_settings(tmp_path: Path) -> None:
    settings = tmp_path / "new" / "settings.json"
    install(settings, policy=tmp_path / "p.json", dry_run=False, run_self_test=False)
    assert len(json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 1


def test_install_rejects_nan_in_settings(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text('{"x": NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="NaN"):
        install(settings, policy=tmp_path / "p.json", dry_run=False, run_self_test=False)
    assert settings.read_text(encoding="utf-8") == '{"x": NaN}'


def test_powershell_command_quotes_paths_and_round_trips(tmp_path: Path) -> None:
    policy = tmp_path / "it's policy.json"
    entry = hook_entry(policy, "powershell")
    quoted = str(policy).replace("'", "''")
    assert entry == {
        "type": "command",
        "shell": "powershell",
        "command": f"& '{sys.executable}' -I -m cc_firewall hook --policy '{quoted}'; "
        "if ($LASTEXITCODE -ne 0) { exit 2 }",
    }
    argv = hook_argv(entry)
    assert argv[0] == sys.executable
    assert argv[argv.index("--policy") + 1] == str(policy)


_SHELLS = [
    "bash",
    pytest.param(
        "powershell",
        marks=pytest.mark.skipif(
            not (shutil.which("pwsh") or shutil.which("powershell")), reason="no PowerShell"
        ),
    ),
]


@pytest.mark.parametrize("shell", _SHELLS)
def test_self_test_gates_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shell: str
) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    policy.write_text('{"rules": []}', encoding="utf-8")

    monkeypatch.setattr(sys, "executable", str(tmp_path / "gone" / "python"))
    with pytest.raises(SelfTestError, match="exited 2"):
        install(settings, policy=policy, dry_run=False, shell=shell)
    assert not settings.exists()

    monkeypatch.undo()
    assert install(settings, policy=policy, dry_run=False, shell=shell).startswith("installed")


def test_uninstall_removes_only_firewall_handlers(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    mine = {"type": "command", "command": "mine"}
    ours = hook_entry(policy)
    stop = [{"hooks": [{"type": "command", "command": "bye"}]}]
    existing = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [mine]},
                {"matcher": "Read", "hooks": [mine, ours]},
                {"matcher": "*", "hooks": [ours]},
                {"matcher": "Edit", "hooks": []},
            ],
            "Stop": stop,
        }
    }
    settings.write_text(json.dumps(existing), encoding="utf-8")

    assert "Read" in uninstall(settings, dry_run=True)
    assert json.loads(settings.read_text(encoding="utf-8")) == existing

    assert uninstall(settings, dry_run=False).startswith("uninstalled")
    assert json.loads(settings.read_text(encoding="utf-8"))["hooks"] == {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [mine]},
            {"matcher": "Read", "hooks": [mine]},
            {"matcher": "Edit", "hooks": []},
        ],
        "Stop": stop,
    }
    assert json.loads(settings.with_name("settings.json.bak").read_text("utf-8")) == existing
    assert uninstall(settings, dry_run=False).startswith("not installed")

    settings.write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": [{"hooks": [ours]}]}}))
    uninstall(settings, dry_run=False)
    assert json.loads(settings.read_text(encoding="utf-8")) == {"model": "opus"}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_install_writes_through_symlink(tmp_path: Path) -> None:
    real = tmp_path / "dotfiles" / "settings.json"
    real.parent.mkdir()
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "settings.json"
    link.symlink_to(real)

    install(link, policy=tmp_path / "p.json", dry_run=False, run_self_test=False)
    assert link.is_symlink()
    assert len(json.loads(real.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 1
