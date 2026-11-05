"""Install the firewall as a PreToolUse hook in Claude Code's settings.json."""

import json
import shutil
import sys
from pathlib import Path
from typing import Any

HOOK_SUFFIX = "-m cc_firewall hook"


def default_settings_path() -> Path:
    """Return the user-level Claude Code settings path."""
    return Path.home() / ".claude" / "settings.json"


def hook_command() -> str:
    """Return the command line the settings entry runs."""
    return f'"{sys.executable}" {HOOK_SUFFIX}'


def _is_ours(entry: object) -> bool:
    hooks = entry.get("hooks") if isinstance(entry, dict) else None
    if not isinstance(hooks, list):
        return False
    return any(
        isinstance(h, dict) and str(h.get("command", "")).endswith(HOOK_SUFFIX) for h in hooks
    )


def add_hook(settings: dict[str, Any]) -> bool:
    """Add the hook entry in place. Return False if it was already present.

    Raises:
        ValueError: ``hooks`` or ``hooks.PreToolUse`` exists with an unexpected type.
    """
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' in settings must be an object")
    entries = hooks.setdefault("PreToolUse", [])
    if not isinstance(entries, list):
        raise ValueError("'hooks.PreToolUse' in settings must be a list")
    if any(_is_ours(e) for e in entries):
        return False
    entries.append({"matcher": "*", "hooks": [{"type": "command", "command": hook_command()}]})
    return True


def install(path: Path, *, dry_run: bool) -> str:
    """Install the hook into the settings file and return a status message or dry-run JSON.

    Raises:
        ValueError: The existing settings file is not a JSON object or has odd hook types.
    """
    settings: dict[str, Any] = {}
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a JSON object")
        settings = loaded
    changed = add_hook(settings)
    rendered = json.dumps(settings, indent=2, ensure_ascii=False)
    if dry_run:
        return rendered
    if not changed:
        return f"already installed in {path}"
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered + "\n", encoding="utf-8")
    return f"installed in {path}"
