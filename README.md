# claude-code-firewall

Declarative deny/ask rules for Claude Code tool calls, with a redacted JSONL audit log.

[![CI](https://github.com/petrhromadka/claude-code-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/petrhromadka/claude-code-firewall/actions/workflows/ci.yml)

`cc-firewall` is a [PreToolUse hook](https://code.claude.com/docs/en/hooks) for Claude Code. Before
each tool call runs, it checks the call's arguments against rules you write in one JSON file. It
then denies the call, asks you to confirm it, or lets it through, and records what it decided.

There is no built-in list of attacks. Your policy holds the only rules there are.

## Why

A coding agent runs commands, reads files and calls MCP tools for you. Claude Code's
[permission rules](https://code.claude.com/docs/en/permissions) match a tool name plus a
tool-specific specifier, such as a command prefix, a path or a domain. They can't run a regular
expression over any input field, such as an MCP tool's argument, and they don't record what was
allowed.

`cc-firewall` adds two things:

- **Rules on any field.** You write a glob or a regex, with an optional exception, for any
  `tool_input` key of any tool, or for all of the call's string values at once.
- **An audit trail.** Every decision goes to a local JSONL file, with secrets redacted.

## Quick start

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/). Works on Linux, macOS and
Windows. No runtime dependencies beyond the standard library.

Install the tool, put a policy in place, then add the hook:

```sh
uv tool install git+https://github.com/petrhromadka/claude-code-firewall
curl -fsSL -o ~/.claude/cc-firewall.json \
  https://raw.githubusercontent.com/petrhromadka/claude-code-firewall/main/examples/policy.json
cc-firewall validate            # ok: 5 rules, mode enforce
cc-firewall install --dry-run   # print the PreToolUse section it would write
cc-firewall install             # add the hook to ~/.claude/settings.json
```

`install` adds one `PreToolUse` entry with matcher `*` to `~/.claude/settings.json`:

```json
{
  "type": "command",
  "command": "'/home/me/.local/share/uv/tools/claude-code-firewall/bin/python' -I -m cc_firewall hook --policy '/home/me/.claude/cc-firewall.json' || exit 2"
}
```

- `-I` runs Python isolated, so a `cc_firewall/` or `json.py` in the project directory can't
  replace the hook's code.
- The policy path is fixed at install time, so changing `HOME` can't point the hook at a missing
  file.
- `|| exit 2` blocks the call if the interpreter or the package is gone. Claude Code treats any
  other non-zero exit as a non-blocking error and would run the tool.

The write is atomic and the previous file is kept as `settings.json.bak`. Running `install` again
changes nothing, or refreshes an entry whose interpreter path has moved. Use `--settings PATH` to
target another settings file.

The [starter policy](examples/policy.json) has five rules:

| id | Tools | Decision | What it does |
| --- | --- | --- | --- |
| `no-env-file` | `Read`, `Edit`, `MultiEdit`, `Write`, `NotebookEdit` | deny | Blocks `.env` and `.env.*` files, except `.env.example` |
| `no-env-search` | `Grep`, `Glob` | deny | Same, for search paths and patterns |
| `confirm-env-shell` | `Bash`, `PowerShell` | ask | Asks before a shell command that mentions a `.env` file |
| `confirm-push` | `Bash`, `PowerShell` | ask | Asks before `git ... push` anywhere in a command |
| `confirm-rm-rf` | `Bash` | ask | Asks before `rm` with both the recursive and force flags, joined or separate |

Dry-run a tool call with `check`. Nothing is logged, and the exit code is `0` for allow and `1` for
ask or deny:

```console
$ cc-firewall check --tool Bash --input '{"command": "cd app && git push origin feature"}'
decision: ask
mode: enforce
rules: confirm-push
reason: cc-firewall: [confirm-push] Confirm git push.

$ cc-firewall check --tool Read --input '{"file_path": "/home/me/app/.env.example"}'
decision: allow
mode: enforce
```

`check` exits `2` when `--input` is not valid JSON or the policy is invalid.

To try a new policy without blocking anything, set `"mode": "audit"` first. Read the log for a
while, then switch to `"enforce"`.

## Commands

| Command | What it does |
| --- | --- |
| `cc-firewall hook [--policy P]` | The hook entry point. Reads the hook JSON on stdin and prints a decision. Claude Code runs it; you don't. |
| `cc-firewall check --tool NAME --input JSON [--policy P]` | Evaluates one tool call. Logs nothing. Exits `0` for allow, `1` for ask or deny. |
| `cc-firewall validate [--policy P]` | Reports every error in the policy file and exits `1` if it has any. |
| `cc-firewall install [--settings PATH] [--policy P] [--dry-run]` | Adds or refreshes the hook in Claude Code settings. Writes a `.bak` first. |
| `cc-firewall log [--tail N] [--decision D]` | Prints the last N audit records (default 20). `D` is `deny`, `ask`, `allow`, `would-deny` or `would-ask`, matched exactly. |

`--policy` defaults to `~/.claude/cc-firewall.json`.

## Policy reference

The policy is one file: `~/.claude/cc-firewall.json`. Project-level policy files are ignored on
purpose, so a repository you clone cannot weaken your rules.

```json
{
  "mode": "enforce",
  "log_allowed": true,
  "rules": [
    {
      "id": "confirm-push",
      "tools": ["Bash"],
      "field": "command",
      "regex": "(?i)\\bgit\\b[^;&|\\n]*\\bpush\\b",
      "decision": "ask",
      "reason": "Confirm git push."
    }
  ]
}
```

Top-level keys:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | `"enforce"` or `"audit"` | `"enforce"` | `enforce` returns deny/ask to Claude Code. `audit` only logs `would-deny` / `would-ask` and lets every call run. |
| `log_allowed` | bool | `true` | Also log calls that no rule matched. |
| `rules` | list | `[]` | The rules, described below. |

Rule keys:

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable name. Shown in the reason and the audit log. |
| `tools` | yes | Non-empty list of tool names or fnmatch patterns, for example `"Bash"` or `"mcp__*"`. Case-sensitive. |
| `field` | yes | The `tool_input` key to test, for example `command` or `file_path`. `"*"` tests every string value in the input, nested ones included. Non-string values never match. |
| `glob` | one of `glob` / `regex` | fnmatch pattern matched against the whole value, treated as a path. Case-insensitive; `\` and `/` are treated the same; `**/` also matches no directory, so `**/.env` matches `.env`. Windows aliases of one file are folded first: trailing dots and spaces (`.env.`) and NTFS stream suffixes (`.env::$DATA`). Prefer `glob` over `regex` for paths. |
| `regex` | one of `glob` / `regex` | Python regular expression, matched anywhere in the value (`re.search`). Case-sensitive unless you add `(?i)`. |
| `unless_glob`, `unless_regex` | no | An exception. A value that matches it does not trigger the rule. |
| `decision` | yes | `"deny"` or `"ask"`. |
| `reason` | yes | Text shown to Claude (deny) or to you in the prompt (ask). |

How the decision is made:

- Every rule is checked. If any matching rule says `deny`, the call is denied. Otherwise, if any
  says `ask`, you are asked. If none match, the call is allowed.
- The reason lists every matching rule, for example
  `cc-firewall: [confirm-push] Confirm git push.`
- An invalid policy file, malformed hook input or an internal error **denies every call** (fail
  closed). Fix the file in an editor outside Claude Code, then run `cc-firewall validate`.
- The installed hook passes `--policy` explicitly, and an explicit policy file that doesn't exist
  also denies every call. Only without `--policy` does a missing default file mean "allow and
  log".
- Unknown keys, a bad regex, or a rule with both or neither of `glob` and `regex` make the
  policy invalid.

The hook always exits `0`. For a deny or ask it prints this on stdout; for an allow it prints
nothing:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "cc-firewall: [confirm-push] Confirm git push."
  }
}
```

## Audit log

Records go to `~/.claude/cc-firewall/audit.jsonl`, one JSON object per line. Set
`CC_FIREWALL_HOME` to use another directory. Above 5 MB the file is rotated, keeping three
previous files (`audit.jsonl.1` to `.3`). On Linux and macOS the directory is created `0700` and
the files `0600`.

```json
{"ts": "2026-11-05T14:02:11Z", "session_id": "3f0c9a52-8a1e-4c55-9d1b-2b7f0e6a41d7", "cwd": "/home/me/app", "tool": "Bash", "decision": "ask", "rules": ["confirm-push"], "input": "{\"command\":\"GH_TOKEN=[REDACTED] git push origin main\"}"}
```

| Field | Meaning |
| --- | --- |
| `ts` | UTC timestamp |
| `session_id`, `cwd` | Taken from the hook payload |
| `tool` | Tool name |
| `decision` | `allow`, `ask`, `deny`, or in audit mode `would-ask` / `would-deny` |
| `rules` | Ids of the matching rules |
| `input` | `tool_input` as JSON, redacted, then cut to 2000 characters |

Redaction replaces two kinds of text with `[REDACTED]`. The first is the value of any environment
variable whose name looks like a credential, such as `*TOKEN*`, `*SECRET*` or `*API_KEY*`. The
second is any text shaped like a common credential: GitHub, GitLab, npm, Slack, Anthropic and
OpenAI-style tokens, AWS access key ids, Google API keys, and whole PEM private key blocks.
Every string in the input, keys included, is redacted before it is serialized, so JSON escaping
can't hide a secret that contains a quote or a backslash. The `cwd` field is redacted too. It's
best-effort. A secret in some other format can still reach the log.

The hook never fails because of logging. If a record can't be written, the decision still stands.

## How it fits with Claude Code's own controls

`cc-firewall` adds to the built-in permissions and the sandbox; it doesn't replace either.

- **It can only tighten.** It returns `deny` or `ask`, never `allow`. Claude Code checks its
  own deny and ask rules whatever a hook returns.
  ([Permissions: precedence](https://code.claude.com/docs/en/permissions))
- **A deny holds in every permission mode**, `bypassPermissions` and
  `--dangerously-skip-permissions` included, because PreToolUse hooks run before the mode check.
  ([Hooks guide](https://code.claude.com/docs/en/hooks-guide))
- **In a non-interactive run (`claude -p`), nobody can answer an `ask`.** If Claude Code denies
  the call there, Claude sees the reason instead.
  ([Hooks reference](https://code.claude.com/docs/en/hooks))
- **The [sandbox](https://code.claude.com/docs/en/sandboxing) is a separate layer.** It isolates
  the filesystem and network of the commands that run. `cc-firewall` only reads a call's
  arguments before it runs.

Built-in permission rules handle simple tool and prefix cases. Use `cc-firewall` when you need a
regex or a field-level check. Use the sandbox to contain what a command does once it runs.

## Limitations

This is defense in depth, not a security boundary. Read [SECURITY.md](SECURITY.md) for the threat
model.

- **Matching is on text, and the text can be rephrased.** Shell variables, aliases, quoting and
  indirection can all express the same action with different text. A rule covers exactly what
  its pattern matches; treat the starter rules as guard rails against accidents, not against an
  adversary.
- **A hook that hangs runs the tool.** Claude Code cancels a hook after its timeout and treats
  that as a non-blocking error. Keep regexes simple; a nested quantifier such as `(a+)+` can make
  the hook hang on crafted input.
- **On Windows the hook command needs Git Bash**, which Claude Code uses to run hooks when it is
  installed. The `'...' || exit 2` form doesn't parse in Windows PowerShell 5.1.
- **It doesn't see what runs.** A script the agent writes and then executes is checked only as
  its command line, never as what the script does.
- **It's only as safe as `~/.claude`.** Anything that can edit `~/.claude/settings.json` or the
  policy file can turn the firewall off, and that includes the agent if your permissions let
  it.
- **The audit log is a local file.** It is not tamper-evident, and its redaction is best-effort.
- **It costs time on every call.** Each tool call starts a Python process.

## Development

```sh
uv sync
uv run ruff check .
uv run ruff format --check .
uv run ty check src
uv run pytest -n auto
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
