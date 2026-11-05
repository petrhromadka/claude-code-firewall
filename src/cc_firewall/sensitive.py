"""Redaction of environment secrets and credential-shaped tokens for the audit log."""

import json
import re
from collections.abc import Mapping
from typing import Any

# Env var names whose values are treated as secrets. `_KEY$` and the `PAT` word catch names
# such as OPENAI_KEY or GH_PAT without matching KEYBOARD, PATH or PATTERN. `PWD$` catches
# DB_PWD; the shell's PWD and OLDPWD (the current and previous directory) are excluded.
SENSITIVE_NAME = re.compile(
    r"""
    TOKEN | SECRET | PASSW | CREDENTIAL | AUTH | SESSION | COOKIE | WEBHOOK
    | API_?KEY | ACCESS_?KEY | PRIVATE_?KEY | _KEY$ | (?:^|_)PAT(?:_|$)
    | PWD$ | PASS$ | _PW$
    | ^AWS_ | ^AZURE_ | ^GCP_ | ^GOOGLE_APPLICATION | DATABASE_URL | _DSN$
    """,
    re.IGNORECASE | re.VERBOSE,
)
NOT_SENSITIVE_NAMES = frozenset({"PWD", "OLDPWD"})

# Well-known credential formats, used only to scrub text before it is logged.
TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    *(
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
        )
    ),
    # The whole PEM block, or everything after the header when the END line is missing.
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    ),
)

MIN_SECRET_LEN = 8


def is_sensitive_name(name: str) -> bool:
    """Return True if an env var with this name holds a secret."""
    return name.upper() not in NOT_SENSITIVE_NAMES and SENSITIVE_NAME.search(name) is not None


def secret_values(env: Mapping[str, str]) -> list[str]:
    """Return values of sensitive env vars long enough to be meaningful, longest first."""
    values = {v for k, v in env.items() if len(v) >= MIN_SECRET_LEN and is_sensitive_name(k)}
    return sorted(values, key=len, reverse=True)


def redact(value: Any, env: Mapping[str, str]) -> Any:
    """Return ``value`` with sensitive env values and credential-shaped tokens replaced.

    Strings are scrubbed directly; dict keys and values and list items are scrubbed
    recursively, so secrets are removed before any serialization can escape them. A number
    whose JSON text contains a secret (a numeric PIN or account id) becomes a redacted string.
    """
    return _redact(value, secret_values(env))


def _redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        for pattern in TOKEN_PATTERNS:
            value = pattern.sub("[REDACTED]", value)
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        text = json.dumps(value)
        redacted = _redact(text, secrets)
        return value if redacted == text else redacted
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in value.items():
            result[_unique_key(result, _redact(k, secrets))] = _redact(v, secrets)
        return result
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    return value


def _unique_key(taken: dict[str, Any], key: str) -> str:
    """Return ``key``, or ``key#2``, ``key#3``... when two keys are equal after redaction."""
    candidate, n = key, 1
    while candidate in taken:
        n += 1
        candidate = f"{key}#{n}"
    return candidate
