"""Server-side body schema validation (X07).

When ``validate_body_schema=True``, ``SoapApplication`` compiles the inline
XSD it builds from the registered services and runs every inbound Body
through it before dispatch.  Requests that don't match the schema fail with
``faultcode="Client"`` *before* hitting the service method.

Run:
    uv add fastapi uvicorn
    uv run python examples/12_schema_validation/server.py
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


class Calc(SoapService):
    __service_name__ = "Calc"
    __tns__ = "http://example.com/calc"

    @soap_operation()
    def square(self, n: int) -> int:
        return n * n


soap_app = SoapApplication(
    service_url="http://127.0.0.1:8012/soap",
    validate_body_schema=True,    # X07 — inline XSD validation
)
soap_app.register(Calc())

app = FastAPI(title="soapbar — schema validation demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8012)
