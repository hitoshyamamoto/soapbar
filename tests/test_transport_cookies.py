"""Session-cookie persistence for HttpTransport.

A tiny localhost server sets a ``sid`` cookie on the first response and reports
whether it received one back on later requests, so we can prove the cookie jar
round-trips (and that ``persist_cookies=False`` opts out). Skipped without httpx.
"""
from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator

import pytest

from soapbar.client.transport import HttpTransport

httpx = pytest.importorskip("httpx")


class _Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self) -> None:
        if self.command == "POST":
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
        seen = "sid=" in self.headers.get("Cookie", "")
        body = b"has-sid" if seen else b"no-sid"
        self.send_response(200)
        if not seen:
            self.send_header("Set-Cookie", "sid=session123; Path=/")
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle  # noqa: N815
    do_POST = _handle  # noqa: N815

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_cookies_persist_across_calls(server: str) -> None:
    transport = HttpTransport()  # persist_cookies=True by default
    try:
        _, _, first = transport.send(server, b"<r/>", {})
        _, _, second = transport.send(server, b"<r/>", {})
        assert first == b"no-sid"  # server had no cookie yet, set one
        assert second == b"has-sid"  # jar carried it to the next call
        assert transport.cookies.get("sid") == "session123"  # readable
    finally:
        transport.close()


def test_cookies_not_persisted_when_disabled(server: str) -> None:
    transport = HttpTransport(persist_cookies=False)
    try:
        _, _, first = transport.send(server, b"<r/>", {})
        _, _, second = transport.send(server, b"<r/>", {})
        assert first == second == b"no-sid"  # jar cleared after each call
        assert transport.cookies.get("sid") is None
    finally:
        transport.close()


def test_cookie_injection(server: str) -> None:
    transport = HttpTransport()
    try:
        transport.cookies.set("sid", "injected", domain="127.0.0.1")
        _, _, body = transport.send(server, b"<r/>", {})
        assert body == b"has-sid"  # the injected cookie was sent
    finally:
        transport.close()


async def test_cookies_persist_across_async_calls(server: str) -> None:
    transport = HttpTransport()
    try:
        _, _, first = await transport.send_async(server, b"<r/>", {})
        _, _, second = await transport.send_async(server, b"<r/>", {})
        assert first == b"no-sid"
        assert second == b"has-sid"
    finally:
        await transport.aclose()
