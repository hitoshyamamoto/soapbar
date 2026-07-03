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
import zlib

from soapbar.core.xml import BodyTooLargeError


def decompress_if_gzipped(
    body: bytes, content_encoding: str, max_size: int | None = None
) -> bytes:
    """Return ``body`` decompressed if ``content_encoding`` declares gzip.

    The caller is expected to gate this on ``soap_app.enable_gzip`` — the
    helper itself does no gating; it just honors what the Content-Encoding
    header declares. If the header does not declare gzip (or is empty),
    the body is returned unchanged.

    When *max_size* is given, decompression is **bounded**: a gzip
    "decompression bomb" (a few KB that inflates to gigabytes) is refused with
    :class:`BodyTooLargeError` instead of being fully expanded in memory. The
    plain ``gzip.decompress`` path (``max_size=None``) is retained only for
    callers that have already bounded their input.

    A malformed gzip payload raises ``gzip.BadGzipFile`` / ``zlib.error`` which
    the caller should translate into an HTTP 400 / SOAP ``Client`` fault.
    """
    if not content_encoding:
        return body
    if "gzip" not in content_encoding.lower():
        return body
    if max_size is None:
        return gzip.decompress(body)
    # Bounded, single-shot decompression: ``max_length`` caps the output; if the
    # stream would produce more than ``max_size`` bytes, ``unconsumed_tail`` is
    # left non-empty, which we treat as a bomb and reject. wbits 16+MAX_WBITS
    # selects the gzip container format.
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = decompressor.decompress(body, max_size + 1)
    if len(out) > max_size or decompressor.unconsumed_tail:
        raise BodyTooLargeError(
            f"Decompressed request body exceeds the server limit "
            f"({max_size} bytes); possible decompression bomb."
        )
    out += decompressor.flush()
    if len(out) > max_size:
        raise BodyTooLargeError(
            f"Decompressed request body exceeds the server limit ({max_size} bytes)."
        )
    return out


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
