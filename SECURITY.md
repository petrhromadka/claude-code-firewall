# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/petrhromadka/claude-code-firewall/security/advisories/new).
Do not open a public issue. Expect a first reply within 7 days.

## Scope and threat model

`cc-firewall` is a **policy layer**, not a sandbox. It sees only the arguments of a tool call
before the call runs. It cannot see what a script that the agent wrote does once it runs, and a
pattern-based rule can be worked around by rephrasing a command. Use it together with Claude
Code's permission settings and its sandbox, not instead of them.

In scope: the hook allowing a call that a valid policy rule matches, a crash or malformed policy
that makes the hook fail open, secrets that reach the audit log unredacted, and `install`
corrupting or dropping existing settings.
