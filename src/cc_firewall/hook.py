"""The PreToolUse hook: parse the payload, evaluate, log, and format the decision."""

import json
from pathlib import Path

from cc_firewall.audit import log_decision
from cc_firewall.engine import evaluate
from cc_firewall.models import HookInput
from cc_firewall.policy import PolicyError, load_policy


def parse_hook_input(raw: str) -> HookInput:
    """Parse the hook JSON payload.

    Raises:
        ValueError: The payload is not a JSON object with a string ``tool_name``.
    """
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("tool_name"), str):
        raise ValueError("hook payload must be an object with a string 'tool_name'")
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        raise ValueError("'tool_input' must be an object")
    return HookInput(
        tool=data["tool_name"],
        tool_input=tool_input,
        session_id=str(data.get("session_id", "")),
        cwd=str(data.get("cwd", "")),
    )


def format_output(decision: str, reason: str) -> str:
    """Return the hook stdout JSON for a deny or ask decision."""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )


def _fail_closed(hook: HookInput | None, reason: str) -> str:
    log_decision(hook, "deny", ())
    return format_output("deny", f"cc-firewall: {reason}")


def run_hook(raw: str, policy_path: Path | None = None) -> str | None:
    """Handle one hook invocation and return the stdout text, or None for no decision.

    Invalid policy, a malformed payload or any internal error yields a deny (fail closed).
    """
    hook = None
    try:
        hook = parse_hook_input(raw)
        policy = load_policy(policy_path)
        verdict = evaluate(policy, hook.tool, hook.tool_input)
    except PolicyError as exc:
        return _fail_closed(hook, f"invalid policy, denying all tool calls: {exc}")
    except Exception as exc:  # fail closed on anything unexpected
        return _fail_closed(hook, f"internal error, denying tool call: {type(exc).__name__}: {exc}")
    if verdict.decision == "allow":
        if policy.log_allowed:
            log_decision(hook, "allow", ())
        return None
    if policy.mode == "audit":
        log_decision(hook, f"would-{verdict.decision}", verdict.rules)
        return None
    log_decision(hook, verdict.decision, verdict.rules)
    return format_output(verdict.decision, verdict.reason)
