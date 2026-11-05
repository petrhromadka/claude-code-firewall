import json
from pathlib import Path

from cc_firewall.install import install


def test_install_is_idempotent_and_preserves_settings(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    existing = {
        "model": "opus",
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "bye"}]}],
        },
    }
    settings.write_text(json.dumps(existing), encoding="utf-8")

    install(settings, dry_run=True)
    assert json.loads(settings.read_text(encoding="utf-8")) == existing

    install(settings, dry_run=False)
    first = settings.read_text(encoding="utf-8")
    assert (
        json.loads(settings.with_name("settings.json.bak").read_text(encoding="utf-8")) == existing
    )
    data = json.loads(first)
    assert data["model"] == "opus"
    assert data["hooks"]["Stop"] == existing["hooks"]["Stop"]
    entries = data["hooks"]["PreToolUse"]
    assert entries[0] == existing["hooks"]["PreToolUse"][0]
    assert len(entries) == 2
    assert entries[1]["matcher"] == "*"
    assert entries[1]["hooks"][0]["command"].endswith("-m cc_firewall hook")

    install(settings, dry_run=False)
    assert settings.read_text(encoding="utf-8") == first


def test_install_creates_missing_settings(tmp_path: Path) -> None:
    settings = tmp_path / "new" / "settings.json"
    install(settings, dry_run=False)
    assert len(json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 1
