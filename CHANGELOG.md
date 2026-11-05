# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-05

### Added

- `install` runs the hook command once through its shell with a harmless `Read` call before
  writing, and refuses with the stderr and a hint if it fails. It also refuses when the policy
  file is missing or invalid ("create the policy first"), and when the self-test call is denied
  because the policy can't be used. `--skip-self-test` overrides both.
- `install --shell bash|powershell`. The entry sets `shell` explicitly; `powershell` writes a
  command that parses in Windows PowerShell 5.1 and 7, for Windows without Git Bash. Running
  `install` again keeps the shell of the existing entry unless `--shell` is given.
- The installed entry sets `onFailure: "block"` and a 30 second `timeout`, so Claude Code
  2.1.295 and later block the call when the hook fails or times out. Older versions rely on the
  `exit 2` fallback, which now also prints where to find `watchdog.log`.
- `cc-firewall uninstall` removes only the firewall's handlers, with an atomic write and a `.bak`.
  `--dry-run` prints exactly what the real run writes.
- `cc-firewall doctor` prints an OK/FAIL checklist of the settings file, hook entry,
  interpreter, a self-test, the policy and the audit directory, and exits `1` on any FAIL. It
  runs a hook command it builds itself, never the command stored in the settings file, adds a
  NOTE when `--policy` differs from the policy the hook reads, and a WARN for slow regexes.
- `cwd_glob` on a rule limits it to sessions whose working directory matches; `check --cwd` sets
  the directory for a dry run. It is a convenience for scoping rules, not a security boundary.
- `schema/policy.schema.json` (JSON Schema draft 2020-12), and a `$schema` key in the policy for
  editor completion. The starter policy uses it.
- An optional `tests` list in the policy, run by `cc-firewall test`. The starter policy carries
  tests for its own rules.
- A starter rule, `no-env-notebook`, that denies `.env` files in `NotebookEdit`'s
  `notebook_path`. The starter policy has six rules.
- `cc-firewall stats [--since YYYY-MM-DD]` counts audit records per decision, rule and tool.
- `cc-firewall log --rule ID` filters records by rule.
- `cc-firewall --version`, and help text for every flag.
- `validate` and `install` warn about regexes with nested quantifiers such as `(a+)+`.
- An unknown policy key gets a "did you mean" suggestion. `check` says when no rule in the
  policy applies to the tool and suggests a close tool name, and adds a hint, such as how to
  write a backslash, when `--input` is not valid JSON.
- Audit records gain a `policy` field: `ok`, `missing` or `invalid`.
- Dependabot updates pre-commit hook revisions.

### Changed

- Exit codes are the same across commands: `0` success, `1` a negative result (`check` ask or
  deny, a failing `test`), `2` the command could not run. `validate` now exits `2` for an invalid
  policy, not `1`. Errors are printed with an `error:` prefix.
- `check` and `validate` with an explicit `--policy` that doesn't exist exit `2`, as the hook
  denies in that case. `validate` without a policy file explains where to copy the starter
  policy.
- A trailing `/**` in `glob` and `cwd_glob` also matches the directory itself, so
  `/home/me/app/**` matches `/home/me/app`. `unless_glob` keeps the strict form, so an exception
  never exempts more than it names.
- `field: "*"` also tests object keys, not only string values.
- The hook evaluates under a 5 second deadline and denies a call that exceeds it. A regex that
  holds the interpreter lock is ended one second later by a `faulthandler` watchdog with status
  1, which the installed command turns into a block. The watchdog writes its traceback to
  `watchdog.log` in the audit directory instead of the hook's stderr.
- `python -m cc_firewall hook` skips the argparse CLI and the install module, which cuts about
  30 ms from every call.
- `log` reads the rotated files too, and prints `no audit records in <path>` when there are none.
- Audit records are written as ASCII JSON, and `log` and `stats` escape control and format
  characters, so a crafted input can't rewrite the terminal.

### Fixed

- `null` for an optional key is rejected, as the schema does, instead of being read as absent.
- The PowerShell command doubles every single-quote character PowerShell accepts, including
  U+2018 to U+201B, so such a character in a path can't end the quoted string.
- Duplicate firewall handlers in the settings file are reduced to one on `install`.
- A `.bak` that is a symbolic link is replaced instead of having its target overwritten.
- Redaction covers the `tool` and `session_id` fields, names ending in `PWD`, `PASS` or `_PW`
  (not the shell's `PWD` and `OLDPWD`), and keeps both keys when two of them redact to the same
  text (the second becomes `key#2`).
- A number in the input that contains a secret value, such as a numeric PIN, is redacted.
- On Linux and macOS an existing audit log with looser permissions is set back to `0600`, and the
  log is opened with `O_NOFOLLOW` where the platform has it.
- Log rotation runs under an `audit.lock` file without waiting, so two hooks never rotate at
  once, and a failed rotation no longer drops the record. A lock left by a crashed hook, dated
  in the future or replaced by a directory is treated as stale.
- Settings files with `NaN` or `Infinity` are rejected instead of being written back as invalid
  JSON.

## [0.1.0] - 2026-11-05

### Added

- A declarative policy engine for Claude Code PreToolUse hooks. It reads one user-level policy
  file, `~/.claude/cc-firewall.json`; project-level files are ignored.
- Rules match tool names or fnmatch patterns, one `tool_input` field or all string values, by glob
  or regex, with optional `unless_glob` / `unless_regex` exceptions. Each rule decides
  `deny` or `ask`, and deny wins over ask.
- `enforce` and `audit` modes. An invalid policy or an internal error denies the call (fail
  closed).
- A JSONL audit log at `~/.claude/cc-firewall/audit.jsonl`, overridable with `CC_FIREWALL_HOME`.
  Inputs are redacted and truncated, and the file rotates at 5 MB.
- The `cc-firewall` CLI, with the `hook`, `check`, `validate`, `install` and `log` commands.
- A starter policy, `examples/policy.json`.

[0.2.0]: https://github.com/petrhromadka/claude-code-firewall/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/petrhromadka/claude-code-firewall/releases/tag/v0.1.0
