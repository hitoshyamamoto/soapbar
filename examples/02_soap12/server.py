"""SOAP 1.2 calculator — same service, one attribute change.

The only difference from ``01_calculator/server_fastapi.py`` is
``__soap_version__ = SoapVersion.SOAP_12``; the WSDL, content-type
(``application/soap+xml``), fault schema, and envelope namespace all flip
accordingly.

Run:
    uv add fastapi uvicorn
    uv run python examples/02_soap12/server.py

    curl -H 'Content-Type: application/soap+xml; charset=utf-8; action=""' \\
         -d @request.xml http://127.0.0.1:8012/soap
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.core.envelope import SoapVersion
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


class CalculatorV12(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"
    __soap_version__ = SoapVersion.SOAP_12

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation()
    def subtract(self, a: int, b: int) -> int:
        return a - b


soap_app = SoapApplication(service_url="http://127.0.0.1:8012/soap")
soap_app.register(CalculatorV12())

app = FastAPI(title="soapbar Calculator (SOAP 1.2)")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8012)
