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

from soapbar.core.exceptions import SoapbarError
from soapbar.core.xml import BodyTooLargeError


class UnsupportedContentEncodingError(SoapbarError, ValueError):
    """Raised when Content-Encoding names a coding soapbar does not decode.

    ``gzip`` (and the no-op ``identity``) are the only inbound codings
    soapbar implements. Anything else — ``deflate``, ``br``, a typo, a
    multi-coding stack like ``gzip, br`` — used to
    be silently ignored by a substring match, handing the undecoded bytes to
    the XML parser and producing a confusing 500 traceback instead of a
    client-facing fault. Raising here lets the caller translate it into a
    SOAP ``Client`` fault instead.
    """


def _content_encoding_codings(content_encoding: str) -> list[str]:
    """Return the effective codings named by a Content-Encoding header:
    exactly tokenised, case-folded, with the legacy alias ``x-gzip``
    normalised to ``gzip`` (RFC 9110 §8.4.1.3) and no-op ``identity``
    tokens dropped.

    Content-Encoding (unlike Accept-Encoding) has no q-value parameters —
    RFC 9110 §8.4 defines it as a plain comma-separated list of codings in
    application order. An empty list means the body carries no coding.
    """
    codings = []
    for coding in content_encoding.split(","):
        coding = coding.strip().lower()
        if coding == "x-gzip":
            coding = "gzip"
        if coding and coding != "identity":
            codings.append(coding)
    return codings


def decompress_if_gzipped(
    body: bytes, content_encoding: str, max_size: int | None = None
) -> bytes:
    """Return ``body`` decompressed if ``content_encoding`` declares gzip.

    The caller is expected to gate this on ``soap_app.enable_gzip`` — the
    helper itself does no gating; it just honors what the Content-Encoding
    header declares. If the header is empty or names only no-op ``identity``
    codings, the body is returned unchanged. A single ``gzip`` (or its legacy
    alias ``x-gzip``, equivalent per RFC 9110 §8.4.1.3) is decompressed.
    Anything else — an unknown coding (``deflate``, ``br``, a typo like
    ``notgzip``, matched exactly rather than by substring) or a multi-coding
    stack (``gzip, br``) — raises ``UnsupportedContentEncodingError`` naming
    the offending codings.

    When *max_size* is given, decompression is **bounded**: a gzip
    "decompression bomb" (a few KB that inflates to gigabytes) is refused with
    ``BodyTooLargeError`` instead of being fully expanded in memory. The
    plain ``gzip.decompress`` path (``max_size=None``) is retained only for
    callers that have already bounded their input.

    A malformed gzip payload raises ``gzip.BadGzipFile`` / ``zlib.error`` which
    the caller should translate into an HTTP 400 / SOAP ``Client`` fault.
    """
    codings = _content_encoding_codings(content_encoding)
    if not codings:
        return body
    if codings != ["gzip"]:
        raise UnsupportedContentEncodingError(", ".join(codings))
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


def _accepts_gzip(accept_encoding: str) -> bool:
    """Whether Accept-Encoding names ``gzip`` with a nonzero qvalue.

    Per RFC 9110 §12.5.3, "a qvalue of 0 means 'not acceptable'", so
    ``gzip;q=0`` must be treated as a refusal, not a request, to compress.
    Each comma-separated item is matched on its coding token alone (the part
    before ``;``) so an unrelated token that merely contains "gzip" —
    ``ungzip``, ``not-gzipped`` — no longer matches by substring. The legacy
    alias ``x-gzip`` counts as ``gzip`` (RFC 9110 §8.4.1.3).
    """
    for item in accept_encoding.split(","):
        params = item.split(";")
        coding = params[0].strip().lower()
        if coding == "x-gzip":
            coding = "gzip"
        if coding != "gzip":
            continue
        q = 1.0
        for param in params[1:]:
            param = param.strip().lower()
            if param.startswith("q="):
                try:
                    q = float(param[2:].strip())
                except ValueError:
                    q = 1.0
        return q > 0
    return False


def compress_response(
    body: bytes,
    accept_encoding: str,
) -> tuple[bytes, str | None]:
    """If the client declared Accept-Encoding: gzip (with a nonzero qvalue),
    return gzipped ``body`` plus the Content-Encoding header value;
    otherwise return ``body`` and ``None``.

    Callers should only invoke this when ``soap_app.enable_gzip`` is True;
    otherwise the default (no compression) preserves pre-0.6.1 behavior.
    """
    if not accept_encoding:
        return body, None
    if not _accepts_gzip(accept_encoding):
        return body, None
    return gzip.compress(body), "gzip"
