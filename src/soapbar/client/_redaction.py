# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Redaction of SOAP envelopes for DEBUG log records.

Client DEBUG logging (added in 0.17.0) writes whole envelopes to a log, which
puts credentials at rest in whatever the deployer's logging stack does with
DEBUG records. This module is the single place that decides what a logged
envelope may contain; ``client.py`` and ``transport.py`` both route through it.

Two kinds of secret are covered:

* ``wsse:Security`` header blocks, which carry the ``UsernameToken`` password.
* Elements whose local name names a secret (``Password``, ``Senha``, …) wherever
  they appear, including the **Body**. Not every service puts credentials in the
  WS-Security header: ``soapbar.contrib.ana``'s CotaOnline operations
  authenticate with ``Login``/``Senha`` as plain Body elements, and a
  header-only rule never sees them.

Redaction here is best-effort and deliberately so — soapbar cannot know the
element names of every service it talks to. It is a safety net under DEBUG
logging, not a guarantee; see ``docs/security.md``.
"""
from __future__ import annotations

#: Ceiling on a single logged envelope, in characters. A response can be
#: megabytes; a log record that size is its own incident. Applied after
#: redaction so truncation can never expose something redaction would have
#: removed.
MAX_LOGGED_CHARS = 8192

#: Stand-in for a redacted element's contents.
_REDACTED = "[redacted by soapbar]"

#: Local element names (lower-cased, namespace-ignored) whose text is a secret.
#: Usernames are deliberately absent: knowing *which* account was used is what
#: makes a DEBUG log worth reading, and a login is not a credential on its own.
_SECRET_LOCAL_NAMES = frozenset({
    "password",
    "passwd",
    "pwd",
    "senha",
    "secret",
    "clientsecret",
    "client_secret",
})


def redact_envelope(raw: bytes) -> str:
    """Return *raw* as text, safe to hand to a logger.

    ``wsse:Security`` blocks are emptied, elements naming a secret have their
    text replaced, and the result is truncated to ``MAX_LOGGED_CHARS``.

    Input that is not parseable XML — an MTOM multipart body, a truncated
    buffer, a proxy's HTML error page — is described rather than dumped. That
    matters for multipart in particular: it embeds an envelope this function
    has *not* walked, so printing the bytes would defeat the redaction.

    Never raises. A logging call must not be able to fail the request it is
    describing, so every failure path degrades to a description of the input.
    """
    # Imported here so importing the client stays cheap for anyone who never
    # turns DEBUG on.
    from soapbar.core.namespaces import NS
    from soapbar.core.xml import local_name, parse_xml, to_string

    try:
        # The project's hardened parser, never ``etree.fromstring``: a response
        # body is attacker-controlled, and a logging path must not be the one
        # route into an unprotected parse.
        root = parse_xml(raw)
    except Exception:
        return f"<{len(raw)} bytes, not parseable as XML (MTOM multipart?); not logged>"

    try:
        redacted = False
        for security in root.iter(f"{{{NS.WSSE}}}Security"):
            for child in list(security):
                security.remove(child)
            security.text = _REDACTED
            redacted = True

        for elem in root.iter():
            if not isinstance(elem.tag, str):
                continue  # comments and PIs are stripped by the parser, but be safe
            if local_name(elem).lower() not in _SECRET_LOCAL_NAMES:
                continue
            if elem.text or len(elem):
                for child in list(elem):
                    elem.remove(child)
                elem.text = _REDACTED
                redacted = True

        text = to_string(root)
    except Exception:
        return f"<{len(raw)} bytes, could not be redacted for logging; not logged>"

    if len(text) > MAX_LOGGED_CHARS:
        text = f"{text[:MAX_LOGGED_CHARS]}… <truncated, {len(text)} chars total>"
    if redacted:
        text += "  <!-- soapbar: credential elements removed before logging -->"
    return text
