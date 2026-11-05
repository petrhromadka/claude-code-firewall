"""Command line interface: hook, check, validate, install and log."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from cc_firewall.audit import read_records
from cc_firewall.engine import evaluate
from cc_firewall.hook import main as hook_main
from cc_firewall.install import default_settings_path, install
from cc_firewall.policy import PolicyError, default_policy_path, load_policy


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
    verdict = evaluate(policy, args.tool, tool_input)
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
    sys.stdout.write(f"ok: {len(policy.rules)} rules, mode {policy.mode}\n")
    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    try:
        policy = (args.policy or default_policy_path()).absolute()
        sys.stdout.write(install(args.settings, policy=policy, dry_run=args.dry_run) + "\n")
    except ValueError as exc:  # json.JSONDecodeError is a ValueError
        sys.stderr.write(f"error: {exc}\n")
        return 2
    return 0


def _cmd_log(args: argparse.Namespace) -> int:
    for line in read_records(args.tail, args.decision):
        sys.stdout.write(line + "\n")
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
    check.add_argument("--policy", type=Path)
    check.set_defaults(func=_cmd_check)

    validate = sub.add_parser("validate", help="validate the policy file")
    validate.add_argument("--policy", type=Path)
    validate.set_defaults(func=_cmd_validate)

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
    inst.set_defaults(func=_cmd_install)

    log = sub.add_parser("log", help="print audit records")
    log.add_argument("--tail", type=int, default=20)
    log.add_argument("--decision", choices=("deny", "ask", "allow", "would-deny", "would-ask"))
    log.set_defaults(func=_cmd_log)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = _build_parser().parse_args(argv)
    return args.func(args)
