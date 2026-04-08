"""Interoperability tests: soapbar client → Spyne server.

Requires spyne >= 2.13 (``uv sync --group dev``).
Tests are skipped automatically when spyne is not installed.
"""
from __future__ import annotations

import io
from typing import Any

import pytest

spyne = pytest.importorskip("spyne")

from spyne import Application, Integer, ServiceBase, rpc  # noqa: E402
from spyne.protocol.soap import Soap11  # noqa: E402
from spyne.server.wsgi import WsgiApplication  # noqa: E402

from soapbar.client.client import SoapClient  # noqa: E402
from soapbar.client.transport import HttpTransport  # noqa: E402
from soapbar.core.binding import (  # noqa: E402
    BindingStyle,
    OperationParameter,
    OperationSignature,
)
from soapbar.core.envelope import SoapVersion  # noqa: E402
from soapbar.core.types import xsd  # noqa: E402


# ---------------------------------------------------------------------------
# Spyne service fixture
# ---------------------------------------------------------------------------


class _CalcService(ServiceBase):
    @rpc(Integer, Integer, _returns=Integer)
    def Add(ctx, a, b):  # noqa: N802
        return a + b


def _make_spyne_wsgi() -> WsgiApplication:
    app = Application(
        [_CalcService],
        tns="http://example.com/calc",
        in_protocol=Soap11(),
        out_protocol=Soap11(),
    )
    return WsgiApplication(app)


def _call_wsgi(wsgi_app: WsgiApplication, environ: dict[str, Any]) -> bytes:
    def start_response(status: str, headers: list[tuple[str, str]], *a: Any) -> Any:
        pass

    chunks = wsgi_app(environ, start_response)
    return b"".join(chunks)


def _get_wsdl(wsgi_app: WsgiApplication) -> bytes:
    environ: dict[str, Any] = {
        "REQUEST_METHOD": "GET",
        "QUERY_STRING": "wsdl",
        "CONTENT_LENGTH": "0",
        "CONTENT_TYPE": "text/xml",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.BytesIO(),
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "8000",
        "PATH_INFO": "/soap",
        "SCRIPT_NAME": "",
        "wsgi.url_scheme": "http",
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    return _call_wsgi(wsgi_app, environ)


# ---------------------------------------------------------------------------
# Custom transport: routes soapbar send() through Spyne WSGI app
# ---------------------------------------------------------------------------


class _SpyneTransport(HttpTransport):
    def __init__(self, wsgi_app: WsgiApplication) -> None:
        super().__init__()
        self._wsgi = wsgi_app

    def send(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, str, bytes]:
        environ: dict[str, Any] = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": headers.get("Content-Type", "text/xml; charset=utf-8"),
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_SOAPACTION": headers.get("SOAPAction", ""),
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.BytesIO(),
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8000",
            "PATH_INFO": "/soap",
            "SCRIPT_NAME": "",
            "QUERY_STRING": "",
            "wsgi.url_scheme": "http",
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        response = _call_wsgi(self._wsgi, environ)
        return 200, "text/xml; charset=utf-8", response


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSpyneInterop:
    """soapbar client ↔ Spyne server interoperability."""

    def _make_client(self, wsgi_app: WsgiApplication) -> SoapClient:
        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Add",
            input_params=[
                OperationParameter("a", int_type),
                OperationParameter("b", int_type),
            ],
            output_params=[OperationParameter("result", int_type)],
            soap_action="http://example.com/calc/Add",
        )
        client = SoapClient.manual(
            "http://localhost:8000/soap",
            binding_style=BindingStyle.RPC_LITERAL,
            soap_version=SoapVersion.SOAP_11,
            transport=_SpyneTransport(wsgi_app),
        )
        client.register_operation(sig)
        return client

    def test_spyne_wsdl_is_valid_xml(self) -> None:
        """Spyne generates parseable WSDL — sanity check for our fixture."""
        from lxml import etree

        wsgi = _make_spyne_wsgi()
        wsdl = _get_wsdl(wsgi)
        assert len(wsdl) > 100
        etree.fromstring(wsdl)  # raises if invalid

    def test_soapbar_client_calls_spyne_server(self) -> None:
        """soapbar sends RPC/Literal SOAP 1.1; Spyne processes it correctly."""
        wsgi = _make_spyne_wsgi()
        client = self._make_client(wsgi)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_soapbar_client_spyne_larger_values(self) -> None:
        """Regression: soapbar serialises/deserialises larger integers via Spyne."""
        wsgi = _make_spyne_wsgi()
        client = self._make_client(wsgi)
        assert client.call("Add", a=100, b=200) == 300
