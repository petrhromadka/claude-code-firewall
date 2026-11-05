# Contributing

Issues and pull requests are welcome. Report security problems privately as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## Setup

```sh
uv sync
```

The package uses only the standard library. A pull request that adds a runtime dependency needs a
strong reason.

## Checks

CI runs these on Linux, macOS and Windows with Python 3.11 and 3.14. Run them before you open a
pull request:

```sh
uv run ruff check .
uv run ruff format --check .
uv run ty check src
uv run pytest -n auto
```

The hooks in [.pre-commit-config.yaml](.pre-commit-config.yaml) run trailing-whitespace,
end-of-file and ruff fixes, plus [gitleaks](https://github.com/gitleaks/gitleaks). Run them with
[prek](https://github.com/j178/prek) or `pre-commit`.

## Pull requests

- Keep each change to one logical topic, and add a test for any behavior you change. A bug fix
  starts with a test that reproduces the bug.
- The hook must fail closed. An error during evaluation, or an invalid policy, must deny the
  call, never allow it.
- Never put real tokens or credentials in tests or fixtures. Build credential-shaped strings
  at runtime if a test needs one.
- Add a line to the unreleased section at the top of [CHANGELOG.md](CHANGELOG.md) for any
  change users will notice.
