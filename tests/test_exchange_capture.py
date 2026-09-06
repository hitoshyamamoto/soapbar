"""Raw-exchange capture: on_exchange callback and last_request/last_response.

The capture carries the exact wire bytes — the request as sent (post-MTOM
packaging) and the response as received (pre-MTOM decoding) — because its
purpose is mandatory archival: a fiscal-document integration must retain
exactly what crossed the wire, failures included.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer
from typing import ClassVar

import pytest

from soapbar import HttpTransport

_OK_BODY = (
    b'<?xml version="1.0"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<soapenv:Body><r>ok</r></soapenv:Body></soapenv:Envelope>"
)


class _Handler(BaseHTTPRequestHandler):
    status: ClassVar[int] = 200
    body: ClassVar[bytes] = _OK_BODY

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        payload = type(self).body
        self.send_response(type(self).status)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server_url():
    _Handler.status = 200
    _Handler.body = _OK_BODY
    server = TCPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/soap"
    finally:
        server.shutdown()
        server.server_close()


_REQUEST = b'<?xml version="1.0"?><probe>1</probe>'
_HEADERS = {"Content-Type": "text/xml", "SOAPAction": '"Probe"'}


def test_callback_and_attributes_capture_wire_bytes(server_url: str) -> None:
    seen: list[tuple[bytes, bytes, str, dict[str, str]]] = []
    transport = HttpTransport(on_exchange=lambda req, resp, url, hdrs: seen.append(
        (req, resp, url, hdrs)
    ))
    status, _ct, _body = transport.send(server_url, _REQUEST, dict(_HEADERS))
    assert status == 200
    assert len(seen) == 1
    req, resp, url, hdrs = seen[0]
    assert req == _REQUEST
    assert resp == _OK_BODY
    assert url == server_url
    assert hdrs["SOAPAction"] == '"Probe"'
    assert transport.last_request == _REQUEST
    assert transport.last_response == _OK_BODY


def test_http_error_responses_are_captured_too(server_url: str) -> None:
    """An archival obligation covers failures: a 500 fault body must reach
    the callback and the attributes exactly as received."""
    _Handler.status = 500
    _Handler.body = b"<fault>boom</fault>"
    seen: list[bytes] = []
    transport = HttpTransport(on_exchange=lambda req, resp, url, hdrs: seen.append(resp))
    status, _ct, body = transport.send(server_url, _REQUEST, dict(_HEADERS))
    assert status == 500
    assert seen == [b"<fault>boom</fault>"]
    assert transport.last_request == _REQUEST, (
        "the urllib HTTPError branch must not clobber the captured request"
    )
    assert transport.last_response == b"<fault>boom</fault>"
    assert body == b"<fault>boom</fault>"


def test_callback_exception_propagates(server_url: str) -> None:
    """A failed archive must be visible, never swallowed."""

    def _failing(req: bytes, resp: bytes, url: str, hdrs: dict[str, str]) -> None:
        raise RuntimeError("archive store unavailable")

    transport = HttpTransport(on_exchange=_failing)
    with pytest.raises(RuntimeError, match="archive store unavailable"):
        transport.send(server_url, _REQUEST, dict(_HEADERS))


async def test_async_path_captures_exchange(server_url: str) -> None:
    pytest.importorskip("httpx")
    seen: list[bytes] = []
    transport = HttpTransport(on_exchange=lambda req, resp, url, hdrs: seen.append(req))
    status, _ct, _body = await transport.send_async(server_url, _REQUEST, dict(_HEADERS))
    assert status == 200
    assert seen == [_REQUEST]
    assert transport.last_response == _OK_BODY
    await transport.aclose()


def test_capture_is_pre_mtom_decode(server_url: str) -> None:
    """last_response is the body as RECEIVED; an MTOM multipart response is
    captured in its multipart form, not the decoded SOAP XML."""
    from soapbar.core.mtom import MtomAttachment, build_mtom

    soap_xml = _OK_BODY
    multipart, outer_ct = build_mtom(
        soap_xml,
        [MtomAttachment(content_id="a", content_type="text/plain", data=b"x")],
        soap_version_content_type="text/xml",
    )

    class _MtomTransport(HttpTransport):
        def _send_httpx(self, url, body, headers):
            self._record_exchange(body, multipart, url, headers)
            ct, content = self._decode_mtom_if_needed(outer_ct, multipart)
            return 200, ct, content

        _send_urllib = _send_httpx

    transport = _MtomTransport()
    _status, ct, decoded = transport.send(server_url, _REQUEST, dict(_HEADERS))
    assert transport.last_response == multipart
    assert b"multipart" not in ct.encode()
    assert b"<r>ok</r>" in decoded
