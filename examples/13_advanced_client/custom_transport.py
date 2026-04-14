"""Custom HttpTransport — short timeout & relaxed SSL verification.

Pass a configured ``HttpTransport`` to ``SoapClient(transport=…)`` to control
network behavior (timeout, TLS verification, retries by subclassing).  This
example uses a 2-second timeout and disables SSL verification — both useful
for development against self-signed dev hosts; never disable verification in
production.

Run (against the calculator from 01_calculator):
    uv run python examples/01_calculator/server_fastapi.py &
    uv run python examples/13_advanced_client/custom_transport.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport


def main() -> None:
    transport = HttpTransport(
        timeout=2.0,        # seconds; raises if the server is slow
        verify_ssl=False,   # accept self-signed certs (DEV ONLY)
    )
    client = SoapClient(
        wsdl_url="http://127.0.0.1:8000/soap?wsdl",
        transport=transport,
    )
    print(f"add(100, 200) = {client.call('add', a=100, b=200)}")


if __name__ == "__main__":
    main()
