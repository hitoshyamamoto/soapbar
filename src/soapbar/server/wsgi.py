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

        if method == "GET" and "wsdl" in query_string.lower():
            wsdl = self.soap_app.get_wsdl()
            start_response("200 OK", [
                ("Content-Type", "text/xml; charset=utf-8"),
                ("Content-Length", str(len(wsdl))),
            ])
            return [wsdl]

        if method == "POST":
            if _is_mtom(content_type):
                from soapbar.core.envelope import SoapVersion, build_fault
                from soapbar.core.xml import to_bytes
                version = SoapVersion.SOAP_12 if "soap+xml" in content_type else SoapVersion.SOAP_11
                msg = "MTOM/XOP is not supported by this endpoint"
                fault_elem = build_fault(version, "Client", msg)
                body_mtom = to_bytes(fault_elem)
                start_response("415 Unsupported Media Type", [
                    ("Content-Type", version.content_type),
                    ("Content-Length", str(len(body_mtom))),
                ])
                return [body_mtom]

            try:
                content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            except ValueError:
                content_length = 0
            wsgi_input = environ.get("wsgi.input")
            body_bytes = wsgi_input.read(content_length) if wsgi_input else b""

            status, resp_ct, resp_body = self.soap_app.handle_request(
                body_bytes, soap_action=soap_action, content_type=content_type
            )
            status_str = f"{status} {'OK' if status == 200 else 'Error'}"
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
