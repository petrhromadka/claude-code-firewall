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

Install the tool, put a policy in place, add the hook, then check the result:

```sh
uv tool install git+https://github.com/petrhromadka/claude-code-firewall
curl -fsSL -o ~/.claude/cc-firewall.json \
  https://raw.githubusercontent.com/petrhromadka/claude-code-firewall/main/examples/policy.json
cc-firewall validate            # ok: 5 rules, mode enforce
cc-firewall test                # 10 passed, 0 failed
cc-firewall install --dry-run   # print the PreToolUse section it would write
cc-firewall install             # add the hook to ~/.claude/settings.json
cc-firewall doctor              # OK/FAIL checklist of the installed hook
```

`install` adds one `PreToolUse` entry with matcher `*` to `~/.claude/settings.json`:

```json
{
  "type": "command",
  "shell": "bash",
  "command": "'/home/me/.local/share/uv/tools/claude-code-firewall/bin/python' -I -m cc_firewall hook --policy '/home/me/.claude/cc-firewall.json' || exit 2",
  "onFailure": "block",
  "timeout": 30
}
```

- `-I` runs Python isolated, so a `cc_firewall/` or `json.py` in the project directory can't
  replace the hook's code.
- The policy path is fixed at install time, so changing `HOME` can't point the hook at a missing
  file.
- `|| exit 2` and `onFailure: "block"` make a hook that can't run block the call instead of
  letting it through. See [Fail closed](#fail-closed).

Before writing, `install` runs the exact command once through that shell with a harmless `Read`
call. If it fails, nothing is written, and you get its stderr and a hint. `--skip-self-test`
writes it anyway. The self-test checks that the command runs, not that your policy is right:
installing before the policy file exists passes and leaves a hook that denies every call, which
`doctor` reports.

The write is atomic and the previous file is kept as `settings.json.bak`. Running `install` again
changes nothing, or refreshes an entry that has gone stale, such as a moved interpreter. Use
`--settings PATH` to target another settings file. `uninstall` removes only the firewall's
handlers, with the same atomic write and `.bak` copy.

After installing, `doctor` should show every line `OK`:

```console
$ cc-firewall doctor
OK   settings: /home/me/.claude/settings.json is valid JSON
OK   hook: current, shell bash
OK   interpreter: /home/me/.local/share/uv/tools/claude-code-firewall/bin/python
OK   self-test: hook command ran and exited 0
OK   policy: /home/me/.claude/cc-firewall.json: 5 rules, mode enforce
OK   audit: /home/me/.claude/cc-firewall is writable
```

It exits `1` if any line is `FAIL`, for example `FAIL hook: no cc-firewall hook in ...; run
cc-firewall install` or `FAIL policy: policy file ... does not exist`.

The [starter policy](examples/policy.json) has five rules and ten tests:

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

### Windows

Claude Code runs hooks in Git Bash when it is installed, so the default `--shell bash` entry
works there; the self-test finds Git Bash next to `git` or through `CLAUDE_CODE_GIT_BASH_PATH`.
Without Git Bash, install with `--shell powershell`. That writes a command that parses in Windows
PowerShell 5.1 and PowerShell 7 and turns any non-zero exit into `exit 2`:

```json
{
  "type": "command",
  "shell": "powershell",
  "command": "& 'C:\\Users\\me\\AppData\\Roaming\\uv\\tools\\claude-code-firewall\\Scripts\\python.exe' -I -m cc_firewall hook --policy 'C:\\Users\\me\\.claude\\cc-firewall.json'; if ($LASTEXITCODE -ne 0) { exit 2 }",
  "onFailure": "block",
  "timeout": 30
}
```

In Git Bash, an argument that looks like a POSIX path, such as `check --cwd /home/me/app`, is
rewritten to a Windows path before `cc-firewall` sees it. Pass a Windows path, or set
`MSYS_NO_PATHCONV=1`.

## Commands

| Command | What it does |
| --- | --- |
| `cc-firewall hook [--policy P]` | The hook entry point. Reads the hook JSON on stdin and prints a decision. Claude Code runs it; you don't. |
| `cc-firewall check --tool NAME --input JSON [--cwd DIR] [--policy P]` | Evaluates one tool call. `--cwd` sets the working directory for `cwd_glob` rules. Logs nothing. Exits `0` for allow, `1` for ask or deny. |
| `cc-firewall validate [--policy P]` | Reports every error in the policy file and exits `1` if it has any. Warns about regexes that may backtrack. |
| `cc-firewall test [--policy P]` | Runs the policy's `tests`. Exits `1` if any fails, `2` if the policy is invalid. |
| `cc-firewall install [--settings PATH] [--policy P] [--shell bash\|powershell] [--skip-self-test] [--dry-run]` | Adds or refreshes the hook in Claude Code settings after a self-test. Writes a `.bak` first. |
| `cc-firewall uninstall [--settings PATH] [--dry-run]` | Removes the firewall's handlers and the entries they leave empty. Writes a `.bak` first. |
| `cc-firewall doctor [--settings PATH] [--policy P]` | Checks the settings file, hook entry, interpreter, a live run of the hook, the policy and the audit directory. Exits `1` on any `FAIL`. |
| `cc-firewall log [--tail N] [--decision D] [--rule ID]` | Prints the last N audit records (default 20). `D` is `deny`, `ask`, `allow`, `would-deny` or `would-ask`, matched exactly; `--rule` keeps records that name that rule. |
| `cc-firewall stats [--since YYYY-MM-DD]` | Counts audit records per decision, rule and tool, from that UTC day on. |

`--policy` defaults to `~/.claude/cc-firewall.json`; for `doctor` it defaults to the file the
installed hook reads.

## Policy reference

The policy is one file: `~/.claude/cc-firewall.json`. Project-level policy files are ignored on
purpose, so a repository you clone cannot weaken your rules.

```json
{
  "$schema": "https://raw.githubusercontent.com/petrhromadka/claude-code-firewall/main/schema/policy.schema.json",
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
  ],
  "tests": [
    {"tool": "Bash", "input": {"command": "cd app && git push origin feature"}, "expect": "ask"}
  ]
}
```

`$schema` points your editor at [schema/policy.schema.json](schema/policy.schema.json) (JSON
Schema draft 2020-12), which gives completion, descriptions and errors for every key while you
edit. `cc-firewall` ignores the key.

Top-level keys:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `$schema` | string | none | Schema URL or path, for editors. |
| `mode` | `"enforce"` or `"audit"` | `"enforce"` | `enforce` returns deny/ask to Claude Code. `audit` only logs `would-deny` / `would-ask` and lets every call run. |
| `log_allowed` | bool | `true` | Also log calls that no rule matched. |
| `rules` | list | `[]` | The rules, described below. |
| `tests` | list | `[]` | Test cases for `cc-firewall test`, described below. The hook never reads them. |

Rule keys:

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable name. Shown in the reason and the audit log. |
| `tools` | yes | Non-empty list of tool names or fnmatch patterns, for example `"Bash"` or `"mcp__*"`. Case-sensitive. |
| `field` | yes | The `tool_input` key to test, for example `command` or `file_path`. `"*"` tests every string value in the input, nested ones included. Non-string values never match. |
| `glob` | one of `glob` / `regex` | fnmatch pattern matched against the whole value, treated as a path. Case-insensitive; `\` and `/` are treated the same; `**/` also matches no directory, so `**/.env` matches `.env`. Windows aliases of one file are folded first: trailing dots and spaces (`.env.`) and NTFS stream suffixes (`.env::$DATA`). Prefer `glob` over `regex` for paths. |
| `regex` | one of `glob` / `regex` | Python regular expression, matched anywhere in the value (`re.search`). Case-sensitive unless you add `(?i)`. |
| `unless_glob`, `unless_regex` | no | An exception. A value that matches it does not trigger the rule. |
| `cwd_glob` | no | The rule applies only when the session's working directory matches this glob, with the same path handling as `glob`. A call without a `cwd` never matches it. |
| `decision` | yes | `"deny"` or `"ask"`. |
| `reason` | yes | Text shown to Claude (deny) or to you in the prompt (ask). |

How the decision is made:

- Every rule is checked. If any matching rule says `deny`, the call is denied. Otherwise, if any
  says `ask`, you are asked. If none match, the call is allowed.
- The reason lists every matching rule, for example
  `cc-firewall: [confirm-push] Confirm git push.`
- Unknown keys, a bad regex, or a rule with both or neither of `glob` and `regex` make the
  policy invalid, and an invalid policy denies every call (see [Fail closed](#fail-closed)).
- `validate` warns about a regex with a nested quantifier, such as `(a+)+`, which can backtrack
  for a long time on crafted input. It is a heuristic and doesn't fail validation:

```console
$ cc-firewall validate --policy slow.json
warning: rules[1] (slow): regex may be slow on some inputs
ok: 2 rules, mode enforce
```

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

### Policy tests

Each entry in `tests` is a simulated call and the decision the policy must give it. `tool`,
`input` (the `tool_input` object) and `expect` (`allow`, `ask` or `deny`) are required; `cwd` is
optional and feeds `cwd_glob` rules. Tests ignore `mode`, so an audit-mode policy is tested as if
it enforced. Run them after every edit. With this rule and two tests:

```json
{
  "rules": [
    {"id": "repo-push", "tools": ["Bash"], "field": "command", "regex": "\\bgit\\b.*\\bpush\\b",
     "cwd_glob": "/home/me/work/**", "decision": "deny", "reason": "No pushes from work repos."}
  ],
  "tests": [
    {"tool": "Bash", "input": {"command": "git push"}, "cwd": "/home/me/work/api", "expect": "deny"},
    {"tool": "Bash", "input": {"command": "git push"}, "cwd": "/home/me/play", "expect": "deny"}
  ]
}
```

the second test fails, because `cwd_glob` limits the rule to `/home/me/work`:

```console
$ cc-firewall test --policy work.json
PASS tests[0] Bash {"command": "git push"} cwd=/home/me/work/api -> deny (rules: repo-push)
FAIL tests[1] Bash {"command": "git push"} cwd=/home/me/play expected deny, got allow (rules: none)
1 passed, 1 failed
```

## Fail closed

When `cc-firewall` can't decide, the call is blocked:

- **An invalid policy, malformed hook input or an internal error denies every call.** Fix the
  file in an editor outside Claude Code, then run `cc-firewall validate`.
- **A missing policy file denies every call** when `--policy` is given, as in the installed hook.
  Only without `--policy` does a missing default file mean "allow and log", recorded with
  `"policy": "missing"`.
- **A slow evaluation is denied, not run.** After 5 seconds a stall, such as a blocked read, ends
  in a deny with the reason `cc-firewall: evaluation exceeded deadline, denying tool call`. A
  backtracking regex holds Python's interpreter lock, so the hook can't answer; one second later
  a `faulthandler` watchdog ends the process with status 1. `CC_FIREWALL_DEADLINE` (seconds) can
  shorten the deadline for tests but not lengthen it.
- **A hook that can't run blocks the call.** Claude Code treats exit codes other than 0 and 2 as
  non-blocking errors and runs the tool, so the installed command turns any other exit (a missing
  interpreter, an uninstalled package, the watchdog) into `exit 2`. On Claude Code 2.1.295 and
  later, `onFailure: "block"` also blocks the call when the hook fails to start or times out, and
  the 30 second `timeout` ends a stuck hook sooner. Older versions rely on `exit 2` alone; a hook
  killed by their timeout lets the tool run.

## Audit log

Records go to `~/.claude/cc-firewall/audit.jsonl`, one JSON object per line. Set
`CC_FIREWALL_HOME` to use another directory. Above 5 MB the file is rotated, keeping three
previous files (`audit.jsonl.1` to `.3`). A hook rotates only while it holds `audit.lock`; a hook
that finds the lock held skips rotation and appends. On Linux and macOS the directory is created
`0700` and the files `0600`, and an existing log with looser permissions is set back to `0600`.

```json
{"ts": "2026-11-05T14:02:11Z", "session_id": "3f0c9a52-8a1e-4c55-9d1b-2b7f0e6a41d7", "cwd": "/home/me/app", "tool": "Bash", "decision": "ask", "policy": "ok", "rules": ["confirm-push"], "input": "{\"command\":\"GH_TOKEN=[REDACTED] git push origin main\"}"}
```

| Field | Meaning |
| --- | --- |
| `ts` | UTC timestamp |
| `session_id`, `cwd` | Taken from the hook payload |
| `tool` | Tool name |
| `decision` | `allow`, `ask`, `deny`, or in audit mode `would-ask` / `would-deny` |
| `policy` | `ok`; `missing` when the default policy file doesn't exist (every call allowed); `invalid` when the policy can't be used (every call denied) |
| `rules` | Ids of the matching rules |
| `input` | `tool_input` as JSON, redacted, then cut to 2000 characters; empty in the record for a call that hit the deadline |

A process ended by the watchdog writes no record.

Redaction replaces two kinds of text with `[REDACTED]`. The first is the value of any environment
variable whose name looks like a credential, such as `*TOKEN*`, `*SECRET*` or `*API_KEY*`. The
second is any text shaped like a common credential: GitHub, GitLab, npm, Slack, Anthropic and
OpenAI-style tokens, AWS access key ids, Google API keys, and whole PEM private key blocks.
Every string in the input, keys included, is redacted before it is serialized, so JSON escaping
can't hide a secret that contains a quote or a backslash. A number whose digits contain a secret
value, such as a numeric PIN, becomes a redacted string. The `cwd` field is redacted too. It's
best-effort. A secret in some other format can still reach the log.

The hook never fails because of logging. If a record can't be written, the decision still stands.

`log --rule ID` shows the records of one rule, and `stats` summarizes the log and its rotated
files, skipping malformed lines:

```console
$ cc-firewall stats --since 2026-11-05
records: 4
decisions:
  ask    2
  deny   1
  allow  1
rules:
  confirm-push  2
  no-env-file   1
top 5 tools:
  Bash  2
  Read  2
```

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
- **It doesn't see what runs.** A script the agent writes and then executes is checked only as
  its command line, never as what the script does.
- **A hand-written hook entry can fail open.** Without `|| exit 2` (or the PowerShell
  equivalent) and on a Claude Code version without `onFailure`, a crash or the watchdog's exit
  lets the tool run. Use `install`, and keep regexes simple.
- **It's only as safe as `~/.claude`.** Anything that can edit `~/.claude/settings.json` or the
  policy file can turn the firewall off, and that includes the agent if your permissions let
  it.
- **The audit log is a local file.** It is not tamper-evident, and its redaction is best-effort.
- **It costs time on every call.** Each tool call starts a Python process. The hook path skips
  the CLI's imports, but interpreter startup remains; on some Windows machines it alone takes
  about a second.

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
