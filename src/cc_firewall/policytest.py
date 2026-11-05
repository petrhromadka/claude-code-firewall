"""Run the test cases stored in a policy's ``tests`` list."""

import json
from dataclasses import dataclass

from cc_firewall.engine import evaluate
from cc_firewall.models import Policy, PolicyTest, Verdict

_INPUT_CHARS = 80


@dataclass(frozen=True)
class CaseResult:
    """The outcome of one policy test case."""

    index: int
    case: PolicyTest
    verdict: Verdict

    @property
    def passed(self) -> bool:
        """Return True if the policy gave the expected decision."""
        return self.verdict.decision == self.case.expect

    def describe(self) -> str:
        """Return one line: PASS or FAIL, the call, the decision and the matched rules."""
        text = json.dumps(self.case.tool_input, ensure_ascii=False)
        if len(text) > _INPUT_CHARS:
            text = text[: _INPUT_CHARS - 3] + "..."
        cwd = f" cwd={self.case.cwd}" if self.case.cwd is not None else ""
        rules = ", ".join(self.verdict.rules) or "none"
        outcome = (
            f"-> {self.verdict.decision}"
            if self.passed
            else f"expected {self.case.expect}, got {self.verdict.decision}"
        )
        status = "PASS" if self.passed else "FAIL"
        return (
            f"{status} tests[{self.index}] {self.case.tool} {text}{cwd} {outcome} (rules: {rules})"
        )


def run_tests(policy: Policy) -> list[CaseResult]:
    """Evaluate every test case against the policy's rules, ignoring ``mode``."""
    return [
        CaseResult(i, case, evaluate(policy, case.tool, case.tool_input, cwd=case.cwd))
        for i, case in enumerate(policy.tests)
    ]
