"""FastAPI + soapbar: SOAP calculator service in ~50 lines.

Run:
    uv add fastapi uvicorn
    uv run python examples/calculator_fastapi.py

Endpoints:
    GET  http://localhost:8000/soap?wsdl   → WSDL
    POST http://localhost:8000/soap        → SOAP 1.1 / 1.2
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.core.binding import BindingStyle
from soapbar.core.envelope import SoapVersion
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"
    __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
    __soap_version__ = SoapVersion.SOAP_11

    @soap_operation(documentation="Add two integers")
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation(documentation="Subtract b from a")
    def subtract(self, a: int, b: int) -> int:
        return a - b

    @soap_operation(documentation="Multiply two integers")
    def multiply(self, a: int, b: int) -> int:
        return a * b


soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(Calculator())

app = FastAPI(title="soapbar Calculator")
app.mount("/soap", AsgiSoapApp(soap_app))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
