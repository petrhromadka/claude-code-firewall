"""Command line interface: hook, check, validate, test, install, uninstall, doctor, log, stats."""

import argparse
import io
import json
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from cc_firewall.audit import parse_record, read_lines, terminal_safe
from cc_firewall.doctor import doctor
from cc_firewall.engine import evaluate
from cc_firewall.hook import main as hook_main
from cc_firewall.install import SHELLS, SelfTestError, default_settings_path, install, uninstall
from cc_firewall.policy import (
    PolicyError,
    default_policy_path,
    load_policy,
    slow_regex_warnings,
)
from cc_firewall.policytest import run_tests
from cc_firewall.stats import collect, format_stats


def _cmd_hook(args: argparse.Namespace) -> int:
    return hook_main(args.policy)


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        tool_input = json.loads(args.input)
        if not isinstance(tool_input, dict):
            raise ValueError("--input must be a JSON object")
        policy = load_policy(args.policy)
    except PolicyError as exc:
        sys.stderr.write("\n".join(exc.errors) + "\n")
        return 2
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    verdict = evaluate(policy, args.tool, tool_input, cwd=args.cwd)
    sys.stdout.write(f"decision: {verdict.decision}\nmode: {policy.mode}\n")
    if verdict.rules:
        sys.stdout.write(f"rules: {', '.join(verdict.rules)}\nreason: {verdict.reason}\n")
    return 0 if verdict.decision == "allow" else 1


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        sys.stderr.write("\n".join(f"error: {e}" for e in exc.errors) + "\n")
        return 1
    for warning in slow_regex_warnings(policy):
        sys.stderr.write(f"warning: {warning}\n")
    sys.stdout.write(f"ok: {len(policy.rules)} rules, mode {policy.mode}\n")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy, required=True)
    except PolicyError as exc:
        sys.stderr.write("\n".join(f"error: {e}" for e in exc.errors) + "\n")
        return 2
    results = run_tests(policy)
    for result in results:
        sys.stdout.write(result.describe() + "\n")
    failed = sum(not r.passed for r in results)
    sys.stdout.write(f"{len(results) - failed} passed, {failed} failed\n")
    return 1 if failed else 0


def _cmd_install(args: argparse.Namespace) -> int:
    try:
        policy = (args.policy or default_policy_path()).absolute()
        message = install(
            args.settings,
            policy=policy,
            dry_run=args.dry_run,
            shell=args.shell,
            run_self_test=not args.skip_self_test,
        )
    except (ValueError, OSError, SelfTestError) as exc:  # JSONDecodeError is a ValueError
        sys.stderr.write(f"error: {exc}\n")
        return 2
    sys.stdout.write(message + "\n")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    try:
        message = uninstall(args.settings, dry_run=args.dry_run)
    except (ValueError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    sys.stdout.write(message + "\n")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report, code = doctor(args.settings, args.policy)
    sys.stdout.write(report + "\n")
    return code


def _escape_unencodable_output() -> None:
    """Print characters stdout's encoding lacks (a Windows code page) as escapes, not crash."""
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")


def _selected(line: str, decision: str | None, rule: str | None) -> bool:
    if decision is None and rule is None:
        return True
    record = parse_record(line)
    return (
        record is not None
        and decision in (None, record["decision"])
        and (rule is None or rule in record["rules"])
    )


def _cmd_log(args: argparse.Namespace) -> int:
    _escape_unencodable_output()
    lines = [line for line in read_lines() if _selected(line, args.decision, args.rule)]
    for line in lines[-args.tail :] if args.tail > 0 else []:
        sys.stdout.write(terminal_safe(line) + "\n")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    _escape_unencodable_output()
    sys.stdout.write(format_stats(collect(args.since)) + "\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cc-firewall", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    hook = sub.add_parser("hook", help="PreToolUse hook entry point (reads JSON on stdin)")
    hook.add_argument(
        "--policy",
        type=Path,
        help="policy file, deny all if missing "
        "(default ~/.claude/cc-firewall.json, allow all if missing)",
    )
    hook.set_defaults(func=_cmd_hook)

    check = sub.add_parser("check", help="dry-run a tool call against the policy")
    check.add_argument("--tool", required=True)
    check.add_argument("--input", required=True, help="tool_input as a JSON object")
    check.add_argument("--cwd", help="working directory, for rules with cwd_glob")
    check.add_argument("--policy", type=Path)
    check.set_defaults(func=_cmd_check)

    validate = sub.add_parser("validate", help="validate the policy file")
    validate.add_argument("--policy", type=Path)
    validate.set_defaults(func=_cmd_validate)

    test = sub.add_parser("test", help="run the test cases in the policy's 'tests' list")
    test.add_argument("--policy", type=Path)
    test.set_defaults(func=_cmd_test)

    inst = sub.add_parser("install", help="add the hook to Claude Code settings")
    inst.add_argument("--settings", type=Path, default=default_settings_path())
    inst.add_argument(
        "--policy",
        type=Path,
        help="policy file the hook reads, stored as an absolute path "
        "(default ~/.claude/cc-firewall.json)",
    )
    inst.add_argument(
        "--dry-run", action="store_true", help="print the new PreToolUse section, write nothing"
    )
    inst.add_argument(
        "--shell",
        choices=SHELLS,
        default="bash",
        help="shell Claude Code runs the hook in (default bash: Git Bash on Windows)",
    )
    inst.add_argument(
        "--skip-self-test", action="store_true", help="write the hook without running it first"
    )
    inst.set_defaults(func=_cmd_install)

    uninst = sub.add_parser("uninstall", help="remove the hook from Claude Code settings")
    uninst.add_argument("--settings", type=Path, default=default_settings_path())
    uninst.add_argument(
        "--dry-run", action="store_true", help="print the new PreToolUse section, write nothing"
    )
    uninst.set_defaults(func=_cmd_uninstall)

    doc = sub.add_parser("doctor", help="check the installed hook, policy and audit log")
    doc.add_argument("--settings", type=Path, default=default_settings_path())
    doc.add_argument(
        "--policy", type=Path, help="policy file to check (default: the one the hook uses)"
    )
    doc.set_defaults(func=_cmd_doctor)

    log = sub.add_parser("log", help="print audit records")
    log.add_argument("--tail", type=int, default=20)
    log.add_argument("--decision", choices=("deny", "ask", "allow", "would-deny", "would-ask"))
    log.add_argument("--rule", metavar="ID", help="only records that name this rule id")
    log.set_defaults(func=_cmd_log)

    stats = sub.add_parser("stats", help="count audit records per decision, rule and tool")
    stats.add_argument(
        "--since",
        type=date.fromisoformat,
        metavar="YYYY-MM-DD",
        help="only records from this UTC day on",
    )
    stats.set_defaults(func=_cmd_stats)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = _build_parser().parse_args(argv)
    return args.func(args)
