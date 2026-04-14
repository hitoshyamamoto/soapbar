"""Reuses the calculator service so the async client has something to call.

Run:
    uv add fastapi uvicorn
    uv run python examples/09_async_client/server.py
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI

from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation()
    def slow_add(self, a: int, b: int) -> int:
        # Sync sleep stays under the GIL so async fan-out at the client is
        # still measurable: the server processes serially per request, but
        # the client can have many in flight.
        import time
        time.sleep(0.2)
        return a + b


soap_app = SoapApplication(service_url="http://127.0.0.1:8009/soap")
soap_app.register(Calculator())

app = FastAPI(title="soapbar — async client demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    _ = asyncio  # silence "unused import"; kept for context with client_async.py
    uvicorn.run(app, host="127.0.0.1", port=8009)
