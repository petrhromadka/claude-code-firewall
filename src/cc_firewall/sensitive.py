"""Redaction of environment secrets and credential-shaped tokens for the audit log."""

import re
from collections.abc import Mapping

SENSITIVE_NAME = re.compile(
    r"(TOKEN|SECRET|PASSW|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|SESSION|COOKIE|"
    r"^AWS_|^AZURE_|^GCP_|^GOOGLE_APPLICATION|DATABASE_URL|_DSN$|WEBHOOK)",
    re.IGNORECASE,
)

# Well-known credential formats, used only to scrub text before it is logged.
TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"gh[pousr]_[A-Za-z0-9]{36,}",
        r"github_pat_[A-Za-z0-9_]{60,}",
        r"sk-ant-[A-Za-z0-9_\-]{20,}",
        r"sk-(?:proj-)?[A-Za-z0-9_\-]{32,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"xox[abprs]-[A-Za-z0-9\-]{10,}",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        r"glpat-[A-Za-z0-9_\-]{20,}",
        r"npm_[A-Za-z0-9]{36}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
)

MIN_SECRET_LEN = 8


def secret_values(env: Mapping[str, str]) -> list[str]:
    """Return values of sensitive env vars long enough to be meaningful, longest first."""
    values = {v for k, v in env.items() if len(v) >= MIN_SECRET_LEN and SENSITIVE_NAME.search(k)}
    return sorted(values, key=len, reverse=True)


def redact(text: str, env: Mapping[str, str]) -> str:
    """Replace sensitive env values and credential-shaped tokens with [REDACTED]."""
    for value in secret_values(env):
        text = text.replace(value, "[REDACTED]")
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text
