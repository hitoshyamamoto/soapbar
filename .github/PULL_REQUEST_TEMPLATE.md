<!-- PRs are squash-merged: the PR title becomes the commit message (English, conventional style: feat/fix/docs/chore/...). -->

## What

<!-- What does this PR change, and why? -->

## Checklist

- [ ] `uv run pytest tests/ -q` passes
- [ ] `uv run ruff check src/ tests/ examples/` and `uv run mypy src/ --strict` pass
- [ ] Public API unchanged, or the change is explained here and `tests/test_public_api.py` was deliberately updated (see [STABILITY.md](../blob/main/STABILITY.md))
- [ ] CHANGELOG.md updated (user-visible changes only)
