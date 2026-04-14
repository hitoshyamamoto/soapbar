"""Two response-mode features in one service:

- ``one_way=True`` — fire-and-forget messaging.  Server returns HTTP 202
  (Accepted) with an empty body per SOAP 1.2 Part 2 §7.5.1.
- JSON dual-mode — when the client sends ``Accept: application/json`` the
  response payload is JSON instead of a SOAP envelope.  Useful for
  bridging SOAP back-ends to JSON front-ends without a translation layer.

Run:
    uv add fastapi uvicorn
    uv run python examples/11_one_way_and_json/server.py
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


class Mixed(SoapService):
    __service_name__ = "Mixed"
    __tns__ = "http://example.com/mixed"

    @soap_operation(one_way=True)
    def emit_log(self, msg: str) -> None:
        print(f"[server] log received: {msg!r}")

    @soap_operation()
    def echo(self, msg: str) -> str:
        return f"echo: {msg}"


soap_app = SoapApplication(service_url="http://127.0.0.1:8011/soap")
soap_app.register(Mixed())

app = FastAPI(title="soapbar — one-way + JSON demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8011)
