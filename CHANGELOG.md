# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added

- `install` runs the hook command once through its shell with a harmless `Read` call before
  writing, and refuses with the stderr and a hint if it fails. `--skip-self-test` overrides.
- `install --shell bash|powershell`. The entry sets `shell` explicitly; `powershell` writes a
  command that parses in Windows PowerShell 5.1 and 7, for Windows without Git Bash.
- The installed entry sets `onFailure: "block"` and a 30 second `timeout`, so Claude Code
  2.1.295 and later block the call when the hook fails or times out. Older versions rely on the
  `|| exit 2` fallback.
- `cc-firewall uninstall` removes only the firewall's handlers, with an atomic write and a `.bak`.
- `cc-firewall doctor` prints an OK/FAIL checklist of the settings file, hook entry,
  interpreter, a live self-test, the policy and the audit directory, and exits `1` on any FAIL.
- `cwd_glob` on a rule limits it to sessions whose working directory matches; `check --cwd` sets
  the directory for a dry run.
- `schema/policy.schema.json` (JSON Schema draft 2020-12), and a `$schema` key in the policy for
  editor completion. The starter policy uses it.
- An optional `tests` list in the policy, run by `cc-firewall test`. The starter policy carries
  ten tests for its own rules.
- `cc-firewall stats [--since YYYY-MM-DD]` counts audit records per decision, rule and tool.
- `cc-firewall log --rule ID` filters records by rule.
- `validate` warns about regexes with nested quantifiers such as `(a+)+`.
- Audit records gain a `policy` field: `ok`, `missing` or `invalid`.
- Dependabot updates pre-commit hook revisions.

### Changed

- The hook evaluates under a 5 second deadline and denies a call that exceeds it. A regex that
  holds the interpreter lock is ended one second later by a `faulthandler` watchdog with status
  1, which the installed command turns into a block.
- `python -m cc_firewall hook` skips the argparse CLI and the install module, which cuts about
  30 ms from every call.

### Fixed

- A number in the input that contains a secret value, such as a numeric PIN, is redacted.
- On Linux and macOS an existing audit log with looser permissions is set back to `0600`.
- Log rotation runs under an `audit.lock` file without waiting, so two hooks never rotate at
  once, and a failed rotation no longer drops the record.
- Settings files with `NaN` or `Infinity` are rejected instead of being written back as invalid
  JSON.

## [0.1.0] - Unreleased

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

[0.2.0]: https://github.com/petrhromadka/claude-code-firewall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/petrhromadka/claude-code-firewall/commits/main
