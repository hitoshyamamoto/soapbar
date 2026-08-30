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
    soapbar implements. Anything else — ``deflate``, ``br``, a typo — used to
    be silently ignored by a substring match, handing the undecoded bytes to
    the XML parser and producing a confusing 500 traceback instead of a
    client-facing fault. Raising here lets the caller translate it into a
    SOAP ``Client`` fault instead.
    """


def _content_encoding_coding(content_encoding: str) -> str:
    """Return the single coding named by a Content-Encoding header, exactly
    matched and case-folded (``""`` if the header is empty/whitespace).

    Content-Encoding (unlike Accept-Encoding) has no q-value parameters —
    RFC 9110 §8.4 defines it as a plain comma-separated list of codings.
    soapbar only ever applies one coding, so only the first token is
    meaningful; a caller with more should reject it as unsupported.
    """
    token = content_encoding.split(",", 1)[0].strip().lower()
    return token


def decompress_if_gzipped(
    body: bytes, content_encoding: str, max_size: int | None = None
) -> bytes:
    """Return ``body`` decompressed if ``content_encoding`` declares gzip.

    The caller is expected to gate this on ``soap_app.enable_gzip`` — the
    helper itself does no gating; it just honors what the Content-Encoding
    header declares. If the header is empty or names ``identity``, the body
    is returned unchanged. Any other coding (``deflate``, ``br``, ...) raises
    ``UnsupportedContentEncodingError`` — matched exactly, not by substring,
    so a header like ``notgzip`` is rejected rather than mistaken for gzip.

    When *max_size* is given, decompression is **bounded**: a gzip
    "decompression bomb" (a few KB that inflates to gigabytes) is refused with
    ``BodyTooLargeError`` instead of being fully expanded in memory. The
    plain ``gzip.decompress`` path (``max_size=None``) is retained only for
    callers that have already bounded their input.

    A malformed gzip payload raises ``gzip.BadGzipFile`` / ``zlib.error`` which
    the caller should translate into an HTTP 400 / SOAP ``Client`` fault.
    """
    coding = _content_encoding_coding(content_encoding)
    if not coding or coding == "identity":
        return body
    if coding != "gzip":
        raise UnsupportedContentEncodingError(coding)
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
    ``ungzip``, ``not-gzipped`` — no longer matches by substring.
    """
    for item in accept_encoding.split(","):
        params = item.split(";")
        coding = params[0].strip().lower()
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
