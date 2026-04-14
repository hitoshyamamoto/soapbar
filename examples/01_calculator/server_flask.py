"""Flask + soapbar: the same calculator on a WSGI framework.

Demonstrates that soapbar is framework-agnostic — identical service class,
different adapter (WsgiSoapApp instead of AsgiSoapApp).

Run:
    uv add flask
    uv run python examples/01_calculator/server_flask.py

Endpoints:
    GET  http://127.0.0.1:5000/soap?wsdl   → WSDL
    POST http://127.0.0.1:5000/soap        → SOAP 1.1
"""
from __future__ import annotations

from flask import Flask
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

from soapbar.server.application import SoapApplication
from soapbar.server.service import SoapService, soap_operation
from soapbar.server.wsgi import WsgiSoapApp


class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"

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
        return a / b


soap_app = SoapApplication(service_url="http://127.0.0.1:5000/soap")
soap_app.register(Calculator())

flask_app = Flask(__name__)

application = DispatcherMiddleware(flask_app, {
    "/soap": WsgiSoapApp(soap_app),
})


if __name__ == "__main__":
    run_simple("127.0.0.1", 5000, application, use_reloader=True)
