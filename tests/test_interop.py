"""Interoperability tests: soapbar ↔ zeep, soapbar ↔ spyne.

Requires zeep >= 4.0 and spyne >= 2.14 (``uv sync --group dev``). Tests are
skipped automatically when the peer library is not installed so that CI
without it still passes.
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


# ---------------------------------------------------------------------------
# Spyne interop (soapbar client ↔ spyne server)
# ---------------------------------------------------------------------------

try:
    import spyne as _spyne  # noqa: F401
    _HAS_SPYNE = True
except ImportError:
    _HAS_SPYNE = False


def _make_spyne_wsgi(soap_version: SoapVersion) -> Any:
    from spyne import Application, Integer, ServiceBase, rpc
    from spyne.protocol.soap import Soap11, Soap12
    from spyne.server.wsgi import WsgiApplication

    class CalcSpyneService(ServiceBase):
        @rpc(Integer, Integer, _returns=Integer)
        def Add(ctx: Any, a: int, b: int) -> int:
            return a + b

    if soap_version == SoapVersion.SOAP_11:
        in_proto: Any = Soap11(validator="lxml")
        out_proto: Any = Soap11()
    else:
        in_proto = Soap12(validator="lxml")
        out_proto = Soap12()

    spyne_app = Application(
        [CalcSpyneService],
        tns="http://example.com/calc",
        name="Calculator",
        in_protocol=in_proto,
        out_protocol=out_proto,
    )
    return WsgiApplication(spyne_app)


class _SpyneWsgiTransport(HttpTransport):
    """Routes soapbar SoapClient requests directly into a spyne WsgiApplication."""

    def __init__(self, wsgi_app: Any) -> None:
        super().__init__()
        self._wsgi = wsgi_app

    def _call_wsgi(
        self,
        method: str,
        body: bytes,
        headers: dict[str, str],
        query_string: str = "",
    ) -> tuple[int, str, bytes]:
        environ: dict[str, Any] = {
            "REQUEST_METHOD": method,
            "CONTENT_TYPE": headers.get("Content-Type", "text/xml; charset=utf-8"),
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_SOAPACTION": headers.get("SOAPAction", ""),
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.BytesIO(),
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8000",
            "PATH_INFO": "/",
            "QUERY_STRING": query_string,
            "wsgi.url_scheme": "http",
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        captured: dict[str, Any] = {"status": 500, "headers": {}}

        def start_response(
            status: str,
            response_headers: list[tuple[str, str]],
            *args: Any,
        ) -> Any:
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = dict(response_headers)

        chunks = self._wsgi(environ, start_response)
        body_out = b"".join(chunks)
        ct = captured["headers"].get("Content-Type", "text/xml")
        return int(captured["status"]), ct, body_out

    def send(  # type: ignore[override]
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        return self._call_wsgi("POST", body, headers)

    def fetch_wsdl(self) -> bytes:
        _status, _ct, data = self._call_wsgi(
            "GET", b"", {"Content-Type": "text/xml"}, query_string="wsdl"
        )
        return data


@pytest.mark.skipif(not _HAS_SPYNE, reason="spyne not installed")
class TestSpyneInterop:
    """soapbar client ↔ spyne server interoperability.

    Symmetric counterpart to :class:`TestZeepInterop`: zeep-client ↔ soapbar-server
    is tested above; here soapbar acts as the client and spyne hosts the service.
    """

    TNS = "http://example.com/calc"

    def _make_client(self, soap_version: SoapVersion) -> SoapClient:
        int_type = _int()
        wsgi = _make_spyne_wsgi(soap_version)
        # Spyne wraps the return value as <AddResponse><AddResult>…</AddResult></AddResponse>
        sig = OperationSignature(
            name="Add",
            input_params=[
                OperationParameter("a", int_type),
                OperationParameter("b", int_type),
            ],
            output_params=[OperationParameter("AddResult", int_type)],
            soap_action="",
            input_namespace=self.TNS,
            output_namespace=self.TNS,
        )
        client = SoapClient.manual(
            "http://localhost:8000/",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            soap_version=soap_version,
            transport=_SpyneWsgiTransport(wsgi),
        )
        client.register_operation(sig)
        return client

    def test_soapbar_client_calls_spyne_server_soap11(self) -> None:
        client = self._make_client(SoapVersion.SOAP_11)
        assert client.call("Add", a=3, b=4) == 7

    def test_soapbar_client_calls_spyne_server_soap12(self) -> None:
        client = self._make_client(SoapVersion.SOAP_12)
        assert client.call("Add", a=10, b=32) == 42

    def test_spyne_wsdl_parseable_by_soapbar(self) -> None:
        from soapbar.core.wsdl.parser import parse_wsdl

        wsgi = _make_spyne_wsgi(SoapVersion.SOAP_11)
        transport = _SpyneWsgiTransport(wsgi)
        wsdl_bytes = transport.fetch_wsdl()
        assert wsdl_bytes.startswith(b"<?xml") or b"definitions" in wsdl_bytes
        defn = parse_wsdl(wsdl_bytes)
        assert defn is not None
