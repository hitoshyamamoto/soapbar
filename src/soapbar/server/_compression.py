# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""HTTP Content-Encoding helpers for WSGI/ASGI adapters (C2 feature).

Gated at the ``SoapApplication(enable_gzip=True)`` level. The helpers here
implement the boring mechanics (gzip library wrappers, Accept-Encoding
parsing); the adapter code decides whether to call them based on
``soap_app.enable_gzip``.
"""
from __future__ import annotations

import gzip


def decompress_if_gzipped(body: bytes, content_encoding: str) -> bytes:
    """Return ``body`` decompressed if ``content_encoding`` declares gzip.

    The caller is expected to gate this on ``soap_app.enable_gzip`` — the
    helper itself does no gating; it just honors what the Content-Encoding
    header declares. If the header does not declare gzip (or is empty),
    the body is returned unchanged.

    A malformed gzip payload raises ``gzip.BadGzipFile`` which the caller
    should translate into an HTTP 400 / SOAP ``Client`` fault.
    """
    if not content_encoding:
        return body
    if "gzip" not in content_encoding.lower():
        return body
    return gzip.decompress(body)


def compress_response(
    body: bytes,
    accept_encoding: str,
) -> tuple[bytes, str | None]:
    """If the client declared Accept-Encoding: gzip, return gzipped ``body``
    plus the Content-Encoding header value; otherwise return ``body`` and
    ``None``.

    Callers should only invoke this when ``soap_app.enable_gzip`` is True;
    otherwise the default (no compression) preserves pre-0.6.1 behavior.
    """
    if not accept_encoding:
        return body, None
    if "gzip" not in accept_encoding.lower():
        return body, None
    return gzip.compress(body), "gzip"
