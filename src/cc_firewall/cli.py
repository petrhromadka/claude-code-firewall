"""Command line interface: hook, check, validate, test, install, uninstall, doctor, log, stats."""

import argparse
import io
import json
import sys
from collections.abc import Sequence
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path

from cc_firewall import __version__
from cc_firewall.audit import audit_path, parse_record, read_lines, terminal_safe
from cc_firewall.doctor import doctor
from cc_firewall.engine import evaluate
from cc_firewall.hook import main as hook_main
from cc_firewall.install import (
    SHELLS,
    SelfTestError,
    default_settings_path,
    install,
    policy_warnings,
    uninstall,
)
from cc_firewall.models import Policy
from cc_firewall.policy import (
    PolicyError,
    default_policy_path,
    load_policy,
    slow_regex_warnings,
    suggest,
)
from cc_firewall.policytest import run_tests
from cc_firewall.stats import collect, format_stats

STANDARD_TOOLS = (
    "Bash",
    "Read",
    "Edit",
    "MultiEdit",
    "Write",
    "NotebookEdit",
    "Grep",
    "Glob",
    "WebFetch",
    "WebSearch",
    "PowerShell",
)
_GLOB_CHARS = frozenset("*?[")
_MISSING_POLICY = "no policy at {}; copy examples/policy.json there (see README Quick start)"


def _cmd_hook(args: argparse.Namespace) -> int:
    return hook_main(args.policy)


def _fail(errors: Sequence[str]) -> int:
    """Print each error with the ``error:`` prefix and return 2, the could-not-run exit code."""
    sys.stderr.write("".join(f"error: {e}\n" for e in errors))
    return 2


def _tool_note(policy: Policy, tool: str) -> str | None:
    """Return a note when no rule lists ``tool``, suggesting the name it may be a typo of."""
    patterns = {pattern for rule in policy.rules for pattern in rule.tools}
    if not patterns or any(fnmatchcase(tool, pattern) for pattern in patterns):
        return None
    names = {p for p in patterns if not _GLOB_CHARS & set(p)} | set(STANDARD_TOOLS)
    hint = suggest(tool, names - {tool})
    note = f"note: no rule applies to tool '{tool}'"
    return f"{note}; tool names are case-sensitive{hint}" if hint else note


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        tool_input = json.loads(args.input)
    except ValueError as exc:
        hint = "Write a backslash as \\\\ or use forward slashes"
        return _fail([f"--input is not valid JSON: {exc}. {hint}"])
    if not isinstance(tool_input, dict):
        return _fail(["--input must be a JSON object"])
    path = args.policy or default_policy_path()
    try:
        policy = load_policy(path, required=args.policy is not None)
    except PolicyError as exc:
        return _fail(exc.errors)
    if not path.exists():
        sys.stderr.write(f"note: no policy file at {path}; every call is allowed\n")
    note = _tool_note(policy, args.tool)
    if note:
        sys.stderr.write(note + "\n")
    verdict = evaluate(policy, args.tool, tool_input, cwd=args.cwd)
    sys.stdout.write(f"decision: {verdict.decision}\nmode: {policy.mode}\n")
    if verdict.rules:
        sys.stdout.write(f"rules: {', '.join(verdict.rules)}\nreason: {verdict.reason}\n")
    return 0 if verdict.decision == "allow" else 1


def _cmd_validate(args: argparse.Namespace) -> int:
    path = args.policy or default_policy_path()
    if not path.exists():
        return _fail([_MISSING_POLICY.format(path)])
    try:
        policy = load_policy(path, required=True)
    except PolicyError as exc:
        return _fail(exc.errors)
    for warning in slow_regex_warnings(policy):
        sys.stderr.write(f"warning: {warning}\n")
    sys.stdout.write(f"ok: {len(policy.rules)} rules, mode {policy.mode}\n")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy, required=True)
    except PolicyError as exc:
        return _fail(exc.errors)
    results = run_tests(policy)
    for result in results:
        sys.stdout.write(result.describe() + "\n")
    failed = sum(not r.passed for r in results)
    sys.stdout.write(f"{len(results) - failed} passed, {failed} failed\n")
    return 1 if failed else 0


def _cmd_install(args: argparse.Namespace) -> int:
    policy = (args.policy or default_policy_path()).absolute()
    try:
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
    if not args.dry_run:
        for warning in policy_warnings(policy):
            sys.stderr.write(f"warning: {warning}\n")
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
    every = read_lines()
    lines = [line for line in every if _selected(line, args.decision, args.rule)]
    if not lines:
        kind = "matching audit records" if every else "audit records"
        sys.stderr.write(f"no {kind} in {audit_path()}\n")
    for line in lines[-args.tail :] if args.tail > 0 else []:
        sys.stdout.write(terminal_safe(line) + "\n")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    _escape_unencodable_output()
    sys.stdout.write(format_stats(collect(args.since)) + "\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cc-firewall", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    settings_help = "Claude Code settings file (default ~/.claude/settings.json)"

    hook = sub.add_parser(
        "hook",
        help="PreToolUse hook entry point (reads JSON on stdin)",
        description="Read one PreToolUse payload on stdin and print the hook decision JSON "
        "(nothing for allow). Exit 0; any problem with the policy or payload ends in a deny.",
    )
    hook.add_argument(
        "--policy",
        type=Path,
        help="policy file; a missing file denies every call. Without --policy, "
        "~/.claude/cc-firewall.json is used and a missing file allows every call.",
    )
    hook.set_defaults(func=_cmd_hook)

    check = sub.add_parser(
        "check",
        help="dry-run a tool call against the policy",
        description="Evaluate one tool call against the policy and print the decision. "
        "Exit 0 allow, 1 ask or deny, 2 bad input or policy.",
    )
    check.add_argument("--tool", required=True, help="tool name, case-sensitive (e.g. Bash)")
    check.add_argument("--input", required=True, help="tool_input as a JSON object")
    check.add_argument("--cwd", help="working directory, for rules with cwd_glob")
    check.add_argument(
        "--policy", type=Path, help="policy file (default ~/.claude/cc-firewall.json)"
    )
    check.set_defaults(func=_cmd_check)

    validate = sub.add_parser(
        "validate",
        help="validate the policy file",
        description="Check that the policy file exists and is valid, and warn about slow "
        "regexes. Exit 0 valid, 2 missing or invalid.",
    )
    validate.add_argument(
        "--policy", type=Path, help="policy file (default ~/.claude/cc-firewall.json)"
    )
    validate.set_defaults(func=_cmd_validate)

    test = sub.add_parser(
        "test",
        help="run the test cases in the policy's 'tests' list",
        description="Run every case in the policy's 'tests' list and print PASS or FAIL for "
        "each. Exit 0 all passed, 1 any failed, 2 missing or invalid policy.",
    )
    test.add_argument(
        "--policy", type=Path, help="policy file (default ~/.claude/cc-firewall.json)"
    )
    test.set_defaults(func=_cmd_test)

    inst = sub.add_parser(
        "install",
        help="add the hook to Claude Code settings",
        description="Add or refresh the cc-firewall PreToolUse hook in Claude Code settings, "
        "after checking the policy and running the hook once. Other settings are kept and "
        "the old file is saved as <settings>.bak. Exit 0 installed, 2 not installed.",
    )
    inst.add_argument("--settings", type=Path, default=default_settings_path(), help=settings_help)
    inst.add_argument(
        "--policy",
        type=Path,
        help="policy file the hook reads, stored as an absolute path "
        "(default ~/.claude/cc-firewall.json)",
    )
    inst.add_argument(
        "--dry-run",
        action="store_true",
        help="print the PreToolUse section install would write; write nothing",
    )
    inst.add_argument(
        "--shell",
        choices=SHELLS,
        help="shell Claude Code runs the hook in (default: the installed entry's shell, "
        "else bash, which is Git Bash on Windows)",
    )
    inst.add_argument(
        "--skip-self-test", action="store_true", help="write the hook without running it first"
    )
    inst.set_defaults(func=_cmd_install)

    uninst = sub.add_parser(
        "uninstall",
        help="remove the hook from Claude Code settings",
        description="Remove the cc-firewall hook from Claude Code settings; other hooks are "
        "kept. Exit 0 removed or not installed, 2 unreadable settings.",
    )
    uninst.add_argument(
        "--settings", type=Path, default=default_settings_path(), help=settings_help
    )
    uninst.add_argument(
        "--dry-run",
        action="store_true",
        help="print the PreToolUse section uninstall would write, or the key it would "
        "remove; write nothing",
    )
    uninst.set_defaults(func=_cmd_uninstall)

    doc = sub.add_parser(
        "doctor",
        help="check the installed hook, policy and audit log",
        description="Check the installed hook entry, its interpreter, a self-test run, the "
        "policy and the audit directory. Exit 0 no failures, 1 any check failed.",
    )
    doc.add_argument("--settings", type=Path, default=default_settings_path(), help=settings_help)
    doc.add_argument(
        "--policy", type=Path, help="policy file to check (default: the one the hook uses)"
    )
    doc.set_defaults(func=_cmd_doctor)

    log = sub.add_parser(
        "log",
        help="print audit records",
        description="Print the newest audit records as JSON lines. Exit 0.",
    )
    log.add_argument("--tail", type=int, default=20, help="number of records (default 20)")
    log.add_argument(
        "--decision",
        choices=("deny", "ask", "allow", "would-deny", "would-ask"),
        help="only records with this decision",
    )
    log.add_argument("--rule", metavar="ID", help="only records that name this rule id")
    log.set_defaults(func=_cmd_log)

    stats = sub.add_parser(
        "stats",
        help="count audit records per decision, rule and tool",
        description="Count audit records per decision, rule and tool. Exit 0.",
    )
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
