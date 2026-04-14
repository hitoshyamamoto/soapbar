"""zeep client calling a soapbar server — cross-stack interop demo.

Proves that existing zeep-based clients call a soapbar backend unchanged.
Use it when migrating a SOAP server to soapbar without touching client code.

Run (start a soapbar server first):
    uv add zeep
    uv run python examples/01_calculator/server_fastapi.py &
    uv run python examples/01_calculator/client_zeep.py
"""
from __future__ import annotations

import sys

try:
    import zeep
except ImportError:
    raise SystemExit("zeep is required for this example: uv add zeep") from None


def main(wsdl_url: str) -> None:
    print("zeep → soapbar interop demo")
    print(f"WSDL: {wsdl_url}")
    print("-" * 40)

    client = zeep.Client(wsdl=wsdl_url)

    print(f"add(3, 4)        = {client.service.add(a=3, b=4)}")
    print(f"subtract(10, 3)  = {client.service.subtract(a=10, b=3)}")
    print(f"multiply(6, 7)   = {client.service.multiply(a=6, b=7)}")
    print(f"divide(10, 2)    = {client.service.divide(a=10, b=2)}")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/soap?wsdl"
    main(url)
