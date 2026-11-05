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

In scope: the hook allowing a call that a valid policy rule matches; a crash, a slow evaluation
or a malformed policy that makes a hook entry written by `install` fail open; secrets that reach
the audit log unredacted; and `install` or `uninstall` corrupting or dropping existing settings.

Known and out of scope: a command rephrased so that no rule's pattern matches it; a command that
acts outside the directory a `cwd_glob` rule is scoped to, since `cwd_glob` is a convenience and
not a boundary; and a hook
entry written by hand without the `exit 2` fallback, on a Claude Code version without
`onFailure: "block"`, letting the tool run when the hook crashes or is killed.
