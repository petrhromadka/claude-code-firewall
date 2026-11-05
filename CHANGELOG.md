# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/petrhromadka/claude-code-firewall/commits/main
