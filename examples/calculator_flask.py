"""Flask + soapbar: same SOAP service on a WSGI framework.

Demonstrates framework-agnostic nature of soapbar — identical service class,
different adapter (WsgiSoapApp instead of AsgiSoapApp).

Run:
    uv add flask
    uv run python examples/calculator_flask.py

Endpoints:
    GET  http://localhost:5000/soap?wsdl   → WSDL
    POST http://localhost:5000/soap        → SOAP 1.1 / 1.2
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


soap_app = SoapApplication(service_url="http://localhost:5000/soap")
soap_app.register(Calculator())

flask_app = Flask(__name__)

# Mount soapbar under /soap; all other paths go to Flask
application = DispatcherMiddleware(flask_app, {
    "/soap": WsgiSoapApp(soap_app),
})

if __name__ == "__main__":
    run_simple("0.0.0.0", 5000, application, use_reloader=True)
