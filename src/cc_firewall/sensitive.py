"""Detection of sensitive environment variables and literal secret tokens."""

import re
from collections.abc import Iterable, Mapping

SENSITIVE_NAME = re.compile(
    r"(TOKEN|SECRET|PASSW|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|SESSION|COOKIE|"
    r"^AWS_|^AZURE_|^GCP_|^GOOGLE_APPLICATION|DATABASE_URL|_DSN$|WEBHOOK)",
    re.IGNORECASE,
)

# Well-known credential formats. Matched against tool input text.
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


def is_sensitive_name(name: str, extra: Iterable[str] = ()) -> bool:
    """Return True if an env var name looks like it holds a credential."""
    return bool(SENSITIVE_NAME.search(name)) or name.upper() in {e.upper() for e in extra}


def secret_values(env: Mapping[str, str], extra: Iterable[str] = ()) -> list[str]:
    """Return values of sensitive env vars long enough to be meaningful, longest first."""
    extra = tuple(extra)
    values = {
        v for k, v in env.items() if len(v) >= MIN_SECRET_LEN and is_sensitive_name(k, extra)
    }
    return sorted(values, key=len, reverse=True)


def find_tokens(text: str) -> list[str]:
    """Return literal credential-shaped substrings found in text."""
    return [m.group(0) for p in TOKEN_PATTERNS for m in p.finditer(text)]


def redact(text: str, env: Mapping[str, str], extra: Iterable[str] = ()) -> str:
    """Replace sensitive env values and credential-shaped tokens with [REDACTED]."""
    for value in secret_values(env, extra):
        text = text.replace(value, "[REDACTED]")
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text
