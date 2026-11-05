import json
from pathlib import Path

import pytest

from cc_firewall.install import hook_entry, install


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

    install(settings, policy=policy, dry_run=False)
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

    assert install(settings, policy=policy, dry_run=False).startswith("installed")
    entries = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert entries == [{"matcher": "Bash|Read", "hooks": [mine, hook_entry(policy)]}]


def test_install_creates_missing_settings(tmp_path: Path) -> None:
    settings = tmp_path / "new" / "settings.json"
    install(settings, policy=tmp_path / "p.json", dry_run=False)
    assert len(json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 1
