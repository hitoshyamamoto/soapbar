# Contributing to soapbar

Thank you for considering a contribution. Issues, discussions, and pull
requests are all welcome.

## No paid solicitations

soapbar does not run paid bounties, and its issue tracker is not a marketplace.
Please do not comment offering to implement an issue for a fee (e.g. "I can do
this for $X, confirm the scope before I begin"). Such comments — especially the
same templated message posted across several issues — will be hidden as spam,
and the account may be blocked and reported. Genuine contributions are always
welcome: open a pull request, or ask a question in an issue or discussion.

## Development setup

soapbar uses [uv](https://docs.astral.sh/uv/) for dependency management:

```bash
git clone https://github.com/hitoshyamamoto/soapbar
cd soapbar
uv sync --group dev --group lint --group type
```

## Before opening a pull request

Run the same checks CI runs:

```bash
# Tests (coverage gate: 93%)
uv run pytest tests/ -q

# Lint
uv run ruff check src/ tests/ examples/

# Type check (strict)
uv run mypy src/ --strict
```

## Tests are required

**As new functionality is added, tests for that functionality MUST be added to
the automated suite in the same pull request.** The same applies to bug fixes: a
fix lands with a regression test that fails before it and passes after.

The 93% coverage gate is a floor, not the policy — a change can clear the gate
without testing anything new. Reviewers check for the tests, not just the
number.

## Coding style

soapbar follows [PEP 8](https://peps.python.org/pep-0008/), enforced
automatically by [ruff](https://docs.astral.sh/ruff/) — the `E` and `W` rules
are pycodestyle and `N` is PEP 8 naming. On top of it the project enables
pyflakes (`F`), import sorting (`I`), pyupgrade (`UP`), bugbear (`B`),
simplify (`SIM`), flake8-bandit security rules (`S`), and ruff's own rules
(`RUF`); see `[tool.ruff]` in `pyproject.toml`.

One deliberate deviation: **line length is 100 characters**, not PEP 8's 79.
Type annotations and XML namespace URIs make 79 counterproductive here.

All public names carry docstrings, and `mypy --strict` must pass — the public
API reference on the documentation site is generated from those docstrings.

## Public API stability

The public surface of soapbar is frozen by a snapshot test
(`tests/test_public_api.py`) and governed by [STABILITY.md](STABILITY.md).
Any change that adds, removes, or alters a public name will fail CI until the
snapshot is deliberately updated — please read STABILITY.md first and explain
the API change in your pull request description.

## Conventions

- Commits, pull requests, and code comments are written in **English**.
- Commit messages follow the conventional style used in the history
  (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).
- Pull requests are squash-merged; the PR title becomes the commit message.
- New third-party GitHub Actions must be pinned to a full commit SHA with a
  version comment, matching the existing workflows.

## Releases

Releases are automated with [release-please](https://github.com/googleapis/release-please):
merged `feat:` and `fix:` PRs accumulate into a rolling **release PR** that
carries the version bump (computed from conventional-commit types: `fix:` →
patch, `feat:` → minor; breaking changes bump minor while pre-1.0) and the
CHANGELOG section, which may be hand-edited on that PR before merging.
Merging the release PR tags the release, publishes to PyPI, and creates the
GitHub Release — no manual version editing or tagging.

To force a release when no `feat:`/`fix:` commits are pending (e.g. a
docs-only release whose docstrings ship in the wheel), merge a commit whose
message body carries a `Release-As: X.Y.Z` footer; release-please will open
the release PR for exactly that version.

## Security issues

Do **not** open a public issue for vulnerabilities. Follow the private
disclosure process in [.github/SECURITY.md](.github/SECURITY.md).
