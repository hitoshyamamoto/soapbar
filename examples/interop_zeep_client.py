"""zeep client calling a soapbar server — live interoperability demo.

Shows that existing zeep-based clients can call a soapbar backend unchanged.
Users migrating from another SOAP server to soapbar do not need to change their
client code.

Run:
    uv add zeep
    uv run python examples/calculator_fastapi.py &   # start soapbar server
    uv run python examples/interop_zeep_client.py
"""
from __future__ import annotations

try:
    import zeep
except ImportError:
    raise SystemExit(
        "zeep is required for this example: uv add zeep"
    ) from None


def main() -> None:
    wsdl_url = "http://localhost:8000/soap?wsdl"

    print("zeep → soapbar interoperability demo")
    print(f"WSDL: {wsdl_url}")
    print("-" * 40)

    client = zeep.Client(wsdl=wsdl_url)

    result = client.service.add(a=3, b=4)
    print(f"add(3, 4)       = {result}")

    result = client.service.subtract(a=10, b=3)
    print(f"subtract(10, 3) = {result}")

    result = client.service.multiply(a=6, b=7)
    print(f"multiply(6, 7)  = {result}")


if __name__ == "__main__":
    main()
