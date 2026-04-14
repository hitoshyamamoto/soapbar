"""WS-Addressing 1.0 server — echoes the caller's wsa:MessageID back.

The soapbar application automatically treats WS-Addressing headers as
"understood" for the mustUnderstand check.  Parsed headers are available at
``envelope.ws_addressing``.  This demo adds an explicit action-handler so the
service logs what it received.

Run:
    uv add fastapi uvicorn
    uv run python examples/05_ws_addressing/server.py
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


class Echo(SoapService):
    __service_name__ = "Echo"
    __tns__ = "http://example.com/echo"

    @soap_operation(soap_action="http://example.com/echo/ping")
    def ping(self, msg: str) -> str:
        return f"echo: {msg}"


soap_app = SoapApplication(service_url="http://127.0.0.1:8005/soap")
soap_app.register(Echo())

app = FastAPI(title="soapbar — WS-Addressing demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8005)
