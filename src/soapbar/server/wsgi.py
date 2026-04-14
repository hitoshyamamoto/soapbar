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
            wsdl = self.soap_app.get_wsdl()
            start_response("200 OK", [
                ("Content-Type", "text/xml; charset=utf-8"),
                ("Content-Length", str(len(wsdl))),
            ])
            return [wsdl]

        if method == "POST":
            try:
                content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            except ValueError:
                content_length = 0
            wsgi_input = environ.get("wsgi.input")
            body_bytes = wsgi_input.read(content_length) if wsgi_input else b""

            # Decode MTOM/XOP into plain XML before dispatch
            if _is_mtom(content_type):
                from soapbar.core.mtom import parse_mtom
                mtom_msg = parse_mtom(body_bytes, content_type)
                body_bytes = mtom_msg.soap_xml
                content_type = (
                    "application/soap+xml; charset=utf-8"
                    if "soap+xml" in content_type
                    else "text/xml; charset=utf-8"
                )

            status, resp_ct, resp_body = self.soap_app.handle_request(
                body_bytes,
                soap_action=soap_action,
                content_type=content_type,
                accept_header=accept,
            )
            _status_texts = {200: "OK", 202: "Accepted", 500: "Internal Server Error"}
            status_str = f"{status} {_status_texts.get(status, 'Error')}"
            start_response(status_str, [
                ("Content-Type", resp_ct),
                ("Content-Length", str(len(resp_body))),
            ])
            return [resp_body]

        # Other methods → 405
        body = b"Method Not Allowed"
        start_response("405 Method Not Allowed", [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
        ])
        return [body]
