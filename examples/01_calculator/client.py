"""soapbar client calling the Calculator service.

Works against either server_fastapi.py (port 8000) or server_flask.py (port 5000);
pass the WSDL URL to switch.

Run (start one of the servers in another terminal first):
    uv run python examples/01_calculator/server_fastapi.py &
    uv run python examples/01_calculator/client.py
"""
from __future__ import annotations

import sys

from soapbar.client.client import SoapClient
from soapbar.core.fault import SoapFault


def main(wsdl_url: str) -> int:
    client = SoapClient(wsdl_url=wsdl_url)

    print("soapbar Calculator client")
    print(f"WSDL: {wsdl_url}")
    print("-" * 40)

    # Happy path
    print(f"add(3, 4)        = {client.call('add',      a=3,  b=4)}")
    print(f"subtract(10, 3)  = {client.call('subtract', a=10, b=3)}")
    print(f"multiply(6, 7)   = {client.call('multiply', a=6,  b=7)}")
    print(f"divide(10, 2)    = {client.call('divide',   a=10, b=2)}")

    # Fault path — server raises ZeroDivisionError, soapbar turns it into a
    # SOAP Fault, the client raises it as SoapFault.
    try:
        client.call("divide", a=1, b=0)
    except SoapFault as fault:
        print(f"\ndivide(1, 0) raised SoapFault as expected:")
        print(f"  faultcode   = {fault.faultcode}")
        print(f"  faultstring = {fault.faultstring}")
        return 0

    print("\nexpected a SoapFault for divide(1, 0) but none was raised", file=sys.stderr)
    return 1


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/soap?wsdl"
    raise SystemExit(main(url))
