"""Interoperability tests: soapbar ↔ zeep.

Requires zeep >= 4.0 (``uv sync --group dev``). Tests are skipped automatically
when zeep is not installed so that CI without zeep still passes.
"""
from __future__ import annotations

import io
from typing import Any

import pytest

zeep = pytest.importorskip("zeep")

from soapbar.client.client import SoapClient  # noqa: E402
from soapbar.client.transport import HttpTransport  # noqa: E402
from soapbar.core.binding import (  # noqa: E402
    BindingStyle,
    OperationParameter,
    OperationSignature,
)
from soapbar.core.envelope import SoapVersion  # noqa: E402
from soapbar.core.types import xsd  # noqa: E402
from soapbar.server.application import SoapApplication  # noqa: E402
from soapbar.server.service import SoapService, soap_operation  # noqa: E402
from soapbar.server.wsgi import WsgiSoapApp  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers shared by all tests
# ---------------------------------------------------------------------------

def _int() -> Any:
    t = xsd.resolve("int")
    assert t is not None
    return t


def _make_calc_app(
    style: BindingStyle = BindingStyle.RPC_LITERAL,
    version: SoapVersion = SoapVersion.SOAP_11,
) -> tuple[SoapApplication, WsgiSoapApp]:
    int_type = _int()

    class CalcService(SoapService):
        __service_name__ = "Calculator"
        __tns__ = "http://example.com/calc"
        __binding_style__ = style
        __soap_version__ = version

        @soap_operation(
            name="Add",
            input_params=[
                OperationParameter("a", int_type),
                OperationParameter("b", int_type),
            ],
            output_params=[
                OperationParameter("result", int_type),
            ],
            soap_action="Add",
        )
        def add(self, a: int, b: int) -> int:
            return a + b

    app = SoapApplication(service_url="http://localhost:8000/soap")
    app.register(CalcService())
    return app, WsgiSoapApp(app)


class _MockResponse:
    """Minimal response object compatible with zeep (only .content is needed)."""

    def __init__(self, content: bytes, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code
        self.headers: dict[str, str] = {"Content-Type": "text/xml; charset=utf-8"}


class _ZeepTransport(zeep.transports.Transport):
    """Routes zeep HTTP calls directly through WsgiSoapApp — no network required."""

    def __init__(self, wsgi_app: WsgiSoapApp, wsdl_bytes: bytes) -> None:
        super().__init__()
        self._wsgi = wsgi_app
        self._wsdl_bytes = wsdl_bytes

    # WSDL fetch ------------------------------------------------------------------
    def load(self, url: str) -> bytes:  # type: ignore[override]
        return self._wsdl_bytes

    # SOAP call -------------------------------------------------------------------
    def post(  # type: ignore[override]
        self,
        address: str,
        message: Any,
        headers: dict[str, str],
    ) -> _MockResponse:
        body: bytes = message if isinstance(message, bytes) else message.encode()

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
            "QUERY_STRING": "",
            "wsgi.url_scheme": "http",
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }

        chunks: list[bytes] = []

        def start_response(
            status: str,
            response_headers: list[tuple[str, str]],
            *args: Any,
        ) -> Any:
            pass

        chunks = self._wsgi(environ, start_response)
        return _MockResponse(b"".join(chunks))


class _InlineTransport(HttpTransport):
    """Routes SoapClient through SoapApplication directly (no network)."""

    def __init__(self, app: SoapApplication) -> None:
        super().__init__()
        self._app = app

    def send(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        soap_action = headers.get("SOAPAction", "").strip('"')
        if not soap_action:
            ct = headers.get("Content-Type", "")
            for part in ct.split(";"):
                part = part.strip()
                if part.startswith("action="):
                    soap_action = part[len("action="):].strip('"')
                    break
        return self._app.handle_request(body, soap_action=soap_action)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestZeepInterop:
    """zeep client ↔ soapbar server interoperability."""

    def test_wsdl_parseable_by_zeep(self) -> None:
        """zeep can parse WSDL auto-generated by soapbar without errors."""
        app, wsgi = _make_calc_app(BindingStyle.RPC_LITERAL)
        wsdl = app.get_wsdl()
        transport = _ZeepTransport(wsgi, wsdl)
        client = zeep.Client(
            wsdl="http://localhost:8000/soap?wsdl",
            transport=transport,
        )
        # Verify the operation is discoverable
        assert client.service.Add is not None

    def test_zeep_client_calls_soapbar_server(self) -> None:
        """zeep sends a SOAP 1.1 RPC/Literal request; soapbar processes it correctly."""
        app, wsgi = _make_calc_app(BindingStyle.RPC_LITERAL, SoapVersion.SOAP_11)
        wsdl = app.get_wsdl()
        transport = _ZeepTransport(wsgi, wsdl)
        client = zeep.Client(
            wsdl="http://localhost:8000/soap?wsdl",
            transport=transport,
        )
        result = client.service.Add(a=3, b=4)
        assert int(result) == 7

    def test_zeep_client_soap12(self) -> None:
        """zeep sends a SOAP 1.2 RPC/Literal request; soapbar processes it correctly."""
        app, wsgi = _make_calc_app(BindingStyle.RPC_LITERAL, SoapVersion.SOAP_12)
        wsdl = app.get_wsdl()
        transport = _ZeepTransport(wsgi, wsdl)
        client = zeep.Client(
            wsdl="http://localhost:8000/soap?wsdl",
            transport=transport,
        )
        result = client.service.Add(a=10, b=32)
        assert int(result) == 42

    def test_zeep_wsdl_dlw_parseable(self) -> None:
        """zeep can parse a Document/Literal/Wrapped WSDL from soapbar."""
        app, wsgi = _make_calc_app(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        wsdl = app.get_wsdl()
        transport = _ZeepTransport(wsgi, wsdl)
        # Should not raise
        client = zeep.Client(
            wsdl="http://localhost:8000/soap?wsdl",
            transport=transport,
        )
        assert client.wsdl is not None


class TestSoapbarSelfInterop:
    """soapbar client ↔ soapbar server round-trip (sanity checks)."""

    def _make_client(
        self,
        style: BindingStyle,
        version: SoapVersion = SoapVersion.SOAP_11,
    ) -> SoapClient:
        int_type = _int()
        app, _ = _make_calc_app(style, version)
        sig = OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type), OperationParameter("b", int_type)],
            output_params=[OperationParameter("result", int_type)],
            soap_action="Add",
        )
        client = SoapClient.manual(
            "http://localhost:8000/soap",
            binding_style=style,
            soap_version=version,
            transport=_InlineTransport(app),
        )
        client.register_operation(sig)
        return client

    def test_soapbar_client_calls_soapbar_server_rpc_literal(self) -> None:
        client = self._make_client(BindingStyle.RPC_LITERAL)
        assert client.call("Add", a=3, b=4) == 7

    def test_soapbar_client_calls_soapbar_server_dlw(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        assert client.call("Add", a=5, b=6) == 11

    def test_soapbar_client_calls_soapbar_server_soap12(self) -> None:
        client = self._make_client(BindingStyle.RPC_LITERAL, SoapVersion.SOAP_12)
        assert client.call("Add", a=100, b=200) == 300
