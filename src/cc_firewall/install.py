"""Install the firewall as a PreToolUse hook in Claude Code's settings.json."""

import json
import shutil
import sys
from pathlib import Path
from typing import Any

HOOK_MARKER = "-m cc_firewall hook"


def default_settings_path() -> Path:
    """Return the user-level Claude Code settings path."""
    return Path.home() / ".claude" / "settings.json"


def hook_command() -> str:
    """Return the command line the settings entry runs.

    Claude Code treats a hook that exits with any code other than 0 or 2 as a non-blocking
    error and runs the tool anyway. ``|| exit 2`` turns a missing interpreter or an
    uninstalled package into a block instead of a silent bypass.
    """
    return f'"{sys.executable}" {HOOK_MARKER} || exit 2'


def _our_hooks(entries: list[Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for entry in entries:
        hooks = entry.get("hooks") if isinstance(entry, dict) else None
        if isinstance(hooks, list):
            found += [
                h for h in hooks if isinstance(h, dict) and HOOK_MARKER in str(h.get("command"))
            ]
    return found


def add_hook(settings: dict[str, Any]) -> bool:
    """Add or refresh the hook entry in place. Return False if it was already current.

    An existing entry with a stale interpreter path is rewritten to the current one.

    Raises:
        ValueError: ``hooks`` or ``hooks.PreToolUse`` exists with an unexpected type.
    """
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' in settings must be an object")
    entries = hooks.setdefault("PreToolUse", [])
    if not isinstance(entries, list):
        raise ValueError("'hooks.PreToolUse' in settings must be a list")
    ours = _our_hooks(entries)
    if ours:
        stale = [h for h in ours if h.get("command") != hook_command()]
        for hook in stale:
            hook["command"] = hook_command()
        return bool(stale)
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
