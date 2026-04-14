"""FastAPI + soapbar: SOAP calculator service in ~60 lines.

Exposes four operations:
- ``add``, ``subtract``, ``multiply``  — arithmetic
- ``divide``  — raises ZeroDivisionError when b == 0 so the paired client can
  demonstrate Fault handling.

Run:
    uv add fastapi uvicorn
    uv run python examples/01_calculator/server_fastapi.py

Endpoints:
    GET  http://127.0.0.1:8000/soap?wsdl   → WSDL
    POST http://127.0.0.1:8000/soap        → SOAP 1.1
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

    @soap_operation(documentation="Divide a by b; b == 0 raises a SOAP fault")
    def divide(self, a: int, b: int) -> float:
        # Any unhandled exception is serialised as a SOAP Fault by soapbar.
        return a / b


soap_app = SoapApplication(service_url="http://127.0.0.1:8000/soap")
soap_app.register(Calculator())

app = FastAPI(title="soapbar Calculator")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
