"""Every public symbol must be mentioned in the documentation.

STABILITY.md commits to every name exported from ``soapbar``; a symbol
nobody can find in docs/ or the README is a commitment without a user
manual. This test fails when a new name enters ``__all__`` without a
documentation mention, so the gap this suite closed cannot silently
reopen. Matching is word-boundary regex, not substring — a substring scan
credits ``to_bytes`` for ``envelope.to_bytes()`` method calls and similar
lookalikes.
"""

from __future__ import annotations

import pathlib
import re

import soapbar

#: Symbols temporarily allowed to lack documentation. Empty on purpose:
#: add a name here only alongside an issue that tracks documenting it.
EXCEPTIONS: set[str] = set()


def _docs_text() -> str:
    root = pathlib.Path(__file__).resolve().parent.parent
    text = (root / "README.md").read_text(encoding="utf-8")
    for page in sorted((root / "docs").glob("*.md")):
        text += page.read_text(encoding="utf-8")
    return text


def test_every_public_symbol_is_documented() -> None:
    text = _docs_text()
    missing = sorted(
        name
        for name in set(soapbar.__all__) - EXCEPTIONS
        if not re.search(rf"\b{re.escape(name)}\b", text)
    )
    assert not missing, (
        f"public symbols with no documentation mention: {missing} — "
        f"document them (docs/ or README.md) or add to EXCEPTIONS with a "
        f"tracking issue"
    )
