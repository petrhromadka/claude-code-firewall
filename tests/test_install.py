import json
import shlex
import shutil
import sys
from pathlib import Path

import pytest

from cc_firewall.cli import main
from cc_firewall.install import (
    SelfTestError,
    hook_argv,
    hook_entry,
    install,
    is_ours,
    self_test,
    uninstall,
)

# Mentions the firewall but does not run it, so install and uninstall must leave it alone.
NOTIFY = {"type": "command", "command": "notify.sh 'cc_firewall: hook fired'"}
HAS_POWERSHELL = bool(shutil.which("pwsh") or shutil.which("powershell"))


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
    python, policy_arg = shlex.quote(sys.executable), shlex.quote(str(policy))
    assert entries[1]["hooks"][0] == {
        "type": "command",
        "shell": "bash",
        "command": f"{python} -I -m cc_firewall hook --policy {policy_arg} || exit 2",
        "onFailure": "block",
        "timeout": 30,
    }

    assert install(settings, policy=policy, dry_run=False).startswith("already installed")
    assert settings.read_text(encoding="utf-8") == first


@pytest.mark.parametrize(
    "stale",
    [
        {"type": "command", "command": '"/old/python" -m cc_firewall hook || exit 2'},
        {"type": "command", "command": "/old/python", "args": ["-m", "cc_firewall", "hook"]},
        {"type": "command", "command": "cc-firewall hook --policy /old/policy.json"},
    ],
)
def test_install_upgrades_stale_entry_in_place(tmp_path: Path, stale: dict[str, object]) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    entry = {"matcher": "Bash|Read", "hooks": [NOTIFY, stale]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [entry]}}), encoding="utf-8")

    result = install(settings, policy=policy, dry_run=False, run_self_test=False)
    assert result.startswith("installed")
    entries = json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert entries == [{"matcher": "Bash|Read", "hooks": [NOTIFY, hook_entry(policy)]}]


def test_install_keeps_first_firewall_handler_and_drops_duplicates(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    ours = hook_entry(policy)
    entries = [
        {"matcher": "Bash", "hooks": [NOTIFY, ours, ours]},
        {"matcher": "*", "hooks": [ours]},
        {"matcher": "Edit", "hooks": []},
    ]
    settings.write_text(json.dumps({"hooks": {"PreToolUse": entries}}), encoding="utf-8")

    assert install(settings, policy=policy, dry_run=False, run_self_test=False) == (
        f"installed in {settings}"
    )
    assert json.loads(settings.read_text(encoding="utf-8"))["hooks"]["PreToolUse"] == [
        {"matcher": "Bash", "hooks": [NOTIFY, ours]},
        {"matcher": "Edit", "hooks": []},
    ]
    assert install(settings, policy=policy, dry_run=False).startswith("already installed")


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
        "onFailure": "block",
        "timeout": 30,
    }
    argv = hook_argv(entry)
    assert argv[0] == sys.executable
    assert argv[argv.index("--policy") + 1] == str(policy)


LEFT, RIGHT = "\N{LEFT SINGLE QUOTATION MARK}", "\N{RIGHT SINGLE QUOTATION MARK}"
LOW, REVERSED = "\N{SINGLE LOW-9 QUOTATION MARK}", "\N{SINGLE HIGH-REVERSED-9 QUOTATION MARK}"


@pytest.mark.parametrize(
    ("name", "quoted"),
    [
        ("it's", "it''s"),
        (f"O{RIGHT}Brien", f"O{RIGHT}{RIGHT}Brien"),
        (f"{LEFT}a{REVERSED}", f"{LEFT}{LEFT}a{REVERSED}{REVERSED}"),
        (f"x{LOW}; exit 0 {LOW}", f"x{LOW}{LOW}; exit 0 {LOW}{LOW}"),
    ],
)
def test_powershell_quoting_doubles_every_single_quote_char(
    tmp_path: Path, name: str, quoted: str
) -> None:
    policy = tmp_path / name / "policy.json"
    policy.parent.mkdir()
    policy.write_text('{"rules": []}', encoding="utf-8")
    entry = hook_entry(policy, "powershell")
    assert f"--policy '{tmp_path / quoted / 'policy.json'}';" in entry["command"]
    argv = hook_argv(entry)
    assert argv[argv.index("--policy") + 1] == str(policy)
    assert is_ours(entry)
    if HAS_POWERSHELL:  # the real parse: a broken quote exits 1 or runs the injected text
        self_test(entry)


_SHELLS = [
    "bash",
    pytest.param(
        "powershell", marks=pytest.mark.skipif(not HAS_POWERSHELL, reason="no PowerShell")
    ),
]


@pytest.mark.parametrize(
    ("args", "error"),
    [
        (["-c", "raise SystemExit(1)"], "exited 1"),
        (["-c", "print('hello')"], "other than hook JSON"),
        (["-I", "-m", "cc_firewall", "hook", "--policy", "missing.json"], "unusable policy"),
    ],
)
def test_self_test_rejects_failed_or_fail_closed_hooks(args: list[str], error: str) -> None:
    with pytest.raises(SelfTestError, match=error):
        self_test({"type": "command", "command": sys.executable, "args": args})


def test_install_cli_refuses_a_hook_that_cannot_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = tmp_path / "settings.json"
    policy = tmp_path / "policy.json"
    argv = ["install", "--settings", str(settings), "--policy", str(policy)]

    assert main(argv) == 2
    assert "create the policy first" in capsys.readouterr().err
    assert not settings.exists()

    policy.write_text('{"rules": []}', encoding="utf-8")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "gone" / "python"))
    assert main(argv) == 2
    assert "exited 2" in capsys.readouterr().err
    assert not settings.exists()

    policy.unlink()
    assert main([*argv, "--skip-self-test"]) == 0
    assert settings.exists()

    rule = {"id": "r", "tools": ["Bash"], "field": "command", "regex": "(a+)+$"}
    rules = [{**rule, "decision": "deny", "reason": "no"}]
    policy.write_text(json.dumps({"rules": rules}), encoding="utf-8")
    assert main([*argv, "--skip-self-test"]) == 0
    assert "warning: rules[0] (r): regex may be slow" in capsys.readouterr().err


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
    mine = NOTIFY
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
    remaining = [
        {"matcher": "Bash", "hooks": [mine]},
        {"matcher": "Read", "hooks": [mine]},
        {"matcher": "Edit", "hooks": []},
    ]

    dry = uninstall(settings, dry_run=True)
    assert json.loads(dry) == {"hooks": {"PreToolUse": remaining}}
    assert json.loads(settings.read_text(encoding="utf-8")) == existing

    assert uninstall(settings, dry_run=False).startswith("uninstalled")
    assert json.loads(settings.read_text(encoding="utf-8"))["hooks"] == {
        "PreToolUse": remaining,
        "Stop": stop,
    }
    assert json.loads(settings.with_name("settings.json.bak").read_text("utf-8")) == existing
    assert uninstall(settings, dry_run=False).startswith("not installed")

    for other, dry_text in [({}, '"hooks" key is removed'), ({"Stop": stop}, '"hooks.PreToolUse"')]:
        written = {"model": "opus", "hooks": {"PreToolUse": [{"hooks": [ours]}], **other}}
        settings.write_text(json.dumps(written), encoding="utf-8")
        assert dry_text in uninstall(settings, dry_run=True)
        uninstall(settings, dry_run=False)
        expected = {"model": "opus", "hooks": other} if other else {"model": "opus"}
        assert json.loads(settings.read_text(encoding="utf-8")) == expected


def test_backup_replaces_a_symlinked_bak_without_writing_its_target(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text('{"model": "opus"}', encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    bak = tmp_path / "settings.json.bak"
    try:
        bak.symlink_to(victim)
    except OSError:
        pytest.skip("cannot create symlinks here")

    install(settings, policy=tmp_path / "p.json", dry_run=False, run_self_test=False)
    assert victim.read_text(encoding="utf-8") == "keep"
    assert not bak.is_symlink()
    assert bak.read_text(encoding="utf-8") == '{"model": "opus"}'


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
