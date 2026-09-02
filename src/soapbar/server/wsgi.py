# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""WSGI adapter for SoapApplication."""
from __future__ import annotations

from typing import Any

from soapbar.server.application import SoapApplication


def _is_mtom(content_type: str) -> bool:
    ct = content_type.lower()
    return "multipart/related" in ct and "application/xop+xml" in ct


class WsgiSoapApp:
    """WSGI application wrapping a ``SoapApplication``.

    The synchronous counterpart of ``AsgiSoapApp``
    for WSGI servers and frameworks (gunicorn, Flask/Werkzeug mounts).
    ``GET ?wsdl`` serves the WSDL; ``POST`` dispatches SOAP envelopes,
    decoding inbound MTOM automatically.
    """

    def __init__(self, soap_app: SoapApplication) -> None:
        self.soap_app = soap_app

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Any,
    ) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        query_string = environ.get("QUERY_STRING", "")
        content_type = environ.get("CONTENT_TYPE", "text/xml")
        soap_action = environ.get("HTTP_SOAPACTION", "").strip('"')
        accept = environ.get("HTTP_ACCEPT", "")

        if method == "GET" and "wsdl" in query_string.lower():
            # X06 — WSDL access control
            _req_headers = {
                k[5:].replace("_", "-").lower(): v
                for k, v in environ.items() if k.startswith("HTTP_")
            }
            if not self.soap_app.check_wsdl_access(_req_headers):
                body = b"WSDL access denied"
                start_response("403 Forbidden", [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", str(len(body))),
                ])
                return [body]
            # ?wsdl=<name> selects one document when the application spans
            # several namespaces; an unknown name is a 404, not a 500.
            from soapbar.server.application import _wsdl_selector
            try:
                wsdl = self.soap_app.get_wsdl(_wsdl_selector(query_string))
            except ValueError as exc:
                body = str(exc).encode()
                start_response("404 Not Found", [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", str(len(body))),
                ])
                return [body]
            start_response("200 OK", [
                ("Content-Type", "text/xml; charset=utf-8"),
                ("Content-Length", str(len(wsdl))),
            ])
            return [wsdl]

        if method == "POST":
            from soapbar.core.xml import BodyTooLargeError
            max_size = self.soap_app.max_body_size
            try:
                content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            except ValueError:
                content_length = 0
            wsgi_input = environ.get("wsgi.input")
            # Never buffer more than one byte past the limit, regardless of the
            # (untrusted) Content-Length — this bounds the raw read itself.
            to_read = max_size + 1 if content_length <= 0 else min(content_length, max_size + 1)
            body_bytes = wsgi_input.read(to_read) if wsgi_input else b""

            # Enforce the body-size limit *before* gzip/MTOM decoding, both of
            # which can inflate a small body into a huge one (decompression bomb
            # / XOP amplification). A breach at any stage is reported through the
            # standard oversized-request fault via _force_oversize.
            oversize = len(body_bytes) > max_size

            # C2 — HTTP-level gzip (opt-in via SoapApplication(enable_gzip=True))
            unsupported_encoding = ""
            if not oversize and self.soap_app.enable_gzip:
                from soapbar.server._compression import (
                    UnsupportedContentEncodingError,
                    decompress_if_gzipped,
                )
                content_encoding = environ.get("HTTP_CONTENT_ENCODING", "")
                try:
                    body_bytes = decompress_if_gzipped(
                        body_bytes, content_encoding, max_size
                    )
                except BodyTooLargeError:
                    oversize = True
                except UnsupportedContentEncodingError as exc:
                    unsupported_encoding = str(exc)

            # Decode MTOM/XOP into plain XML before dispatch
            if not oversize and not unsupported_encoding and _is_mtom(content_type):
                from soapbar.core.mtom import parse_mtom
                try:
                    mtom_msg = parse_mtom(body_bytes, content_type, max_size)
                    body_bytes = mtom_msg.soap_xml
                    content_type = (
                        "application/soap+xml; charset=utf-8"
                        if "soap+xml" in content_type
                        else "text/xml; charset=utf-8"
                    )
                except BodyTooLargeError:
                    oversize = True

            status, resp_ct, resp_body = self.soap_app.handle_request(
                b"" if (oversize or unsupported_encoding) else body_bytes,
                soap_action=soap_action,
                content_type=content_type,
                accept_header=accept,
                _force_oversize=oversize,
                _unsupported_encoding=unsupported_encoding,
            )
            # C2 — compress outbound if the client advertised Accept-Encoding: gzip.
            resp_content_encoding: str | None = None
            if self.soap_app.enable_gzip:
                from soapbar.server._compression import compress_response
                resp_body, resp_content_encoding = compress_response(
                    resp_body,
                    environ.get("HTTP_ACCEPT_ENCODING", ""),
                )
            _status_texts = {
                200: "OK",
                202: "Accepted",
                400: "Bad Request",
                500: "Internal Server Error",
            }
            status_str = f"{status} {_status_texts.get(status, 'Error')}"
            resp_headers: list[tuple[str, str]] = [
                ("Content-Type", resp_ct),
                ("Content-Length", str(len(resp_body))),
            ]
            if resp_content_encoding:
                resp_headers.append(("Content-Encoding", resp_content_encoding))
            start_response(status_str, resp_headers)
            return [resp_body]

        # Other methods → 405
        body = b"Method Not Allowed"
        start_response("405 Method Not Allowed", [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
