"""soapbar client calling the Calculator service.

Works against the FastAPI server (calculator_fastapi.py) or the Flask server
(calculator_flask.py) — or any SOAP server that exposes the same WSDL.

Run (start the server first in another terminal):
    uv run python examples/calculator_fastapi.py &
    uv run python examples/calculator_client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.core.fault import SoapFault


def main() -> None:
    # Fetch WSDL from the running server and build a typed client automatically.
    client = SoapClient(wsdl_url="http://localhost:8000/soap?wsdl")

    print("soapbar Calculator client")
    print("-" * 30)

    try:
        result = client.call("add", a=3, b=4)
        print(f"add(3, 4)       = {result}")

        result = client.call("subtract", a=10, b=3)
        print(f"subtract(10, 3) = {result}")

        result = client.call("multiply", a=6, b=7)
        print(f"multiply(6, 7)  = {result}")

    except SoapFault as fault:
        print(f"SOAP fault: {fault.faultcode} — {fault.faultstring}")


if __name__ == "__main__":
    main()
