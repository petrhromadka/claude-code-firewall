"""Install the firewall as a PreToolUse hook in Claude Code's settings.json."""

import contextlib
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

_OURS = re.compile(r"\bcc_firewall\b.*\bhook\b", re.DOTALL)


def default_settings_path() -> Path:
    """Return the user-level Claude Code settings path."""
    return Path.home() / ".claude" / "settings.json"


def hook_entry(policy: Path) -> dict[str, Any]:
    """Return the hook handler that runs the firewall with ``policy`` (an absolute path).

    ``-I`` runs Python isolated: the project directory Claude Code starts the hook in is not
    put on ``sys.path``, so a planted ``cc_firewall/`` or ``json.py`` there cannot replace the
    firewall's code; ``PYTHON*`` variables and user site-packages are ignored as well.

    Claude Code treats exit codes other than 0 and 2 as non-blocking errors and runs the tool
    anyway. The hook's own errors already end in a deny, so ``|| exit 2`` covers the rest: a
    missing interpreter, an uninstalled package or a crash before the hook code runs. That
    needs a shell, so this is shell form (Git Bash on Windows) rather than exec-form ``args``.
    No ``timeout`` is set: the documented default is 600 seconds, and with no documented way
    to make a cancelled hook block, a shorter one would only let the tool run sooner.
    """
    argv = [sys.executable, "-I", "-m", "cc_firewall", "hook", "--policy", str(policy)]
    return {"type": "command", "command": f"{shlex.join(argv)} || exit 2"}


def _is_ours(hook: object) -> bool:
    if not isinstance(hook, dict):
        return False
    args = hook.get("args")
    parts = [hook.get("command", ""), *(args if isinstance(args, list) else [])]
    return bool(_OURS.search(" ".join(map(str, parts))))


def _handler_lists(entries: list[Any]) -> list[list[Any]]:
    handlers = [e.get("hooks") for e in entries if isinstance(e, dict)]
    return [h for h in handlers if isinstance(h, list)]


def add_hook(settings: dict[str, Any], policy: Path) -> bool:
    """Add the hook entry or rewrite stale ones in place. Return False if already current.

    Raises:
        ValueError: ``hooks`` or ``hooks.PreToolUse`` exists with an unexpected type.
    """
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' in settings must be an object")
    entries = hooks.setdefault("PreToolUse", [])
    if not isinstance(entries, list):
        raise ValueError("'hooks.PreToolUse' in settings must be a list")
    expected = hook_entry(policy)
    found = changed = False
    for handlers in _handler_lists(entries):
        for i, handler in enumerate(handlers):
            if _is_ours(handler):
                found = True
                changed |= handler != expected
                handlers[i] = expected
    if not found:
        entries.append({"matcher": "*", "hooks": [expected]})
    return changed or not found


def _write_atomic(path: Path, text: str) -> None:
    """Replace the file behind ``path`` (following symlinks) with ``text`` in one step."""
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        if target.exists():
            shutil.copymode(target, tmp)
        Path(tmp).replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def install(path: Path, *, policy: Path, dry_run: bool) -> str:
    """Install the hook into the settings file and return a status message.

    With ``dry_run`` the message is the resulting ``hooks.PreToolUse`` section only, so other
    settings (such as tokens in ``env``) are not printed.

    Raises:
        ValueError: The existing settings file is not a JSON object, has odd hook types, or
            holds values (NaN, Infinity) that cannot be written back as JSON.
    """
    settings: dict[str, Any] = {}
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a JSON object")
        settings = loaded
    changed = add_hook(settings, policy)
    if dry_run:
        section = {"hooks": {"PreToolUse": settings["hooks"]["PreToolUse"]}}
        return json.dumps(section, indent=2, ensure_ascii=False, allow_nan=False)
    if not changed:
        return f"already installed in {path}"
    try:
        rendered = json.dumps(settings, indent=2, ensure_ascii=False, allow_nan=False)
    except ValueError as exc:
        raise ValueError(f"{path} cannot be written back as JSON, not changed: {exc}") from exc
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    _write_atomic(path, rendered + "\n")
    return f"installed in {path}"
