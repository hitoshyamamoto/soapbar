# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""WSDL retrieval failures and bounded remote-import reads (issue #219).

Two properties, both verified against a real local HTTP server rather than
mocks, because the point is how the two HTTP stacks behave:

* ``HttpTransport.fetch`` raises one exception type, ``WsdlFetchError``, for a
  non-2xx answer on *both* the httpx path and the urllib fallback. Before, the
  same 404 surfaced as ``httpx.HTTPStatusError`` on one and
  ``urllib.error.HTTPError`` on the other, so no single ``except`` covered it.
* A remote ``xsd:import`` is read in chunks and refused with
  ``BodyTooLargeError`` past ``_IMPORT_FETCH_MAX_BYTES`` — before the body is
  materialised, which is what the memory assertion checks.
"""
from __future__ import annotations

import sys
import threading
import tracemalloc
import urllib.error
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from soapbar import BodyTooLargeError, SoapbarError, SoapClient, WsdlFetchError
from soapbar.client.transport import HttpTransport
from soapbar.core.wsdl import parser as wsdl_parser
from soapbar.core.wsdl.parser import parse_wsdl

_STREAM_TOTAL = 2 * 1024 * 1024       # what /big.xsd is willing to send
_TEST_CEILING = 256 * 1024            # the ceiling the parser is patched to


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/missing"):
            body = b"<html><body><h1>404 Not Found</h1></body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/big.xsd"):
            # Stream without a Content-Length, well past the ceiling: the
            # reader must give up on the bytes actually received, not on a
            # header it could not trust anyway.
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"<!-- " + b"x" * (64 * 1024 - 10) + b" -->"
            sent = 0
            try:
                while sent < _STREAM_TOTAL:
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    sent += len(chunk)
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client hung up at the ceiling — expected
            return
        body = b"<ok/>"
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence the test log
        pass


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# fetch(): one exception type on both HTTP stacks
# ---------------------------------------------------------------------------

def test_wsdl_fetch_error_is_a_soapbar_error() -> None:
    assert issubclass(WsdlFetchError, SoapbarError)
    err = WsdlFetchError("http://example.com/x?wsdl", 503)
    assert err.url == "http://example.com/x?wsdl"
    assert err.status == 503
    assert str(err) == "WSDL fetch failed: HTTP 503 for http://example.com/x?wsdl"


def test_fetch_404_on_the_urllib_path(
    base_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "httpx", None)  # force the urllib fallback
    with pytest.raises(WsdlFetchError) as excinfo:
        HttpTransport().fetch(f"{base_url}/missing.wsdl")
    assert excinfo.value.status == 404
    assert excinfo.value.url.endswith("/missing.wsdl")
    assert isinstance(excinfo.value.__cause__, urllib.error.HTTPError)


def test_fetch_404_on_the_httpx_path(base_url: str) -> None:
    httpx = pytest.importorskip("httpx")
    with HttpTransport() as transport, pytest.raises(WsdlFetchError) as excinfo:
        transport.fetch(f"{base_url}/missing.wsdl")
    assert excinfo.value.status == 404
    assert isinstance(excinfo.value.__cause__, httpx.HTTPStatusError)


def test_fetch_success_is_unchanged_on_both_paths(
    base_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with HttpTransport() as transport:
        assert transport.fetch(f"{base_url}/ok.wsdl") == b"<ok/>"
    monkeypatch.setitem(sys.modules, "httpx", None)
    assert HttpTransport().fetch(f"{base_url}/ok.wsdl") == b"<ok/>"


def test_soap_client_surfaces_wsdl_fetch_error(base_url: str) -> None:
    """End to end: a 404 WSDL URL is one `except SoapbarError` away, not a
    stack-specific exception pointing at an HTML document."""
    with pytest.raises(SoapbarError) as excinfo:
        SoapClient(wsdl_url=f"{base_url}/missing.wsdl")
    assert isinstance(excinfo.value, WsdlFetchError)
    assert excinfo.value.status == 404


# ---------------------------------------------------------------------------
# _fetch_wsdl_source: bounded read of a remote import
# ---------------------------------------------------------------------------

def _wsdl_importing(location: str) -> bytes:
    return f"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="urn:t">
  <types>
    <xsd:schema targetNamespace="urn:t">
      <xsd:import namespace="urn:big" schemaLocation="{location}"/>
    </xsd:schema>
  </types>
</definitions>""".encode()


def test_remote_import_read_is_bounded(
    base_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remote import that streams past the ceiling is refused with
    BodyTooLargeError, and the oversized body is never materialised."""
    monkeypatch.setattr(wsdl_parser, "_IMPORT_FETCH_MAX_BYTES", _TEST_CEILING)
    tracemalloc.start()
    try:
        with pytest.raises(BodyTooLargeError, match="exceeds the size limit"):
            parse_wsdl(_wsdl_importing(f"{base_url}/big.xsd"), allow_remote_imports=True)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # The server offers 2 MiB; the reader must stop near the 256 KiB ceiling.
    assert peak < _STREAM_TOTAL // 2, f"peak {peak} bytes — body was materialised"


def test_remote_import_under_the_ceiling_still_resolves(
    base_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ceiling is a guard, not a regression: a small import still loads."""
    monkeypatch.setattr(wsdl_parser, "_IMPORT_FETCH_MAX_BYTES", _TEST_CEILING)
    # /ok.wsdl answers <ok/>, which is a well-formed (if empty) schema target.
    defn = parse_wsdl(_wsdl_importing(f"{base_url}/ok.wsdl"), allow_remote_imports=True)
    assert defn is not None


def test_default_ceiling_mirrors_the_body_size_defaults() -> None:
    assert wsdl_parser._IMPORT_FETCH_MAX_BYTES == 10 * 1024 * 1024
    assert HttpTransport().max_response_size == wsdl_parser._IMPORT_FETCH_MAX_BYTES
