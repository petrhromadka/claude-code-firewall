"""Shared data types: configuration, findings and decisions."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    """User-level firewall configuration (loaded from ~/.claude/cc-firewall.json).

    Attributes:
        mode: "enforce" denies matching calls, "audit" only logs them.
        allowed_hosts: fnmatch host patterns that may receive sensitive env vars.
        allowed_push: fnmatch patterns on "host/owner/repo" allowed as push targets.
            Empty means "same host/owner as the repo's origin remote".
        extra_secret_paths: extra fnmatch path patterns treated as secret files.
        allow_paths: fnmatch path patterns never treated as secret files.
        extra_sensitive_env: extra env var names treated as sensitive.
        log_allowed: also write allowed calls to the audit log.
        fail_open: on an internal error allow the call instead of denying it.
    """

    mode: str = "enforce"
    allowed_hosts: tuple[str, ...] = (
        "api.github.com",
        "uploads.github.com",
        "api.anthropic.com",
    )
    allowed_push: tuple[str, ...] = ()
    extra_secret_paths: tuple[str, ...] = ()
    allow_paths: tuple[str, ...] = ()
    extra_sensitive_env: tuple[str, ...] = ()
    log_allowed: bool = True
    fail_open: bool = False


@dataclass(frozen=True)
class Finding:
    """One rule match: a stable rule id and a human-readable reason."""

    rule: str
    reason: str


@dataclass(frozen=True)
class Decision:
    """Result of evaluating one tool call."""

    findings: tuple[Finding, ...] = field(default=())

    @property
    def blocked(self) -> bool:
        """True when at least one rule matched."""
        return bool(self.findings)
