"""Load a WSDL straight from disk via ``SoapClient.from_file``.

Bundle the WSDL with your application instead of fetching it at startup —
removes a network dependency from the cold path and lets you pin to a
known-good contract.

Run (using a WSDL fetched once from the calculator service):
    uv run python examples/01_calculator/server_fastapi.py &
    curl -s http://127.0.0.1:8000/soap?wsdl > /tmp/calculator.wsdl
    uv run python examples/13_advanced_client/from_file_client.py /tmp/calculator.wsdl
"""
from __future__ import annotations

import sys

from soapbar.client.client import SoapClient


def main(wsdl_path: str) -> None:
    client = SoapClient.from_file(wsdl_path)
    # SoapClient.from_file does NOT pre-populate _address from a WSDL with
    # multiple bindings; the calculator service is single-binding so the
    # address is auto-detected.
    print(f"address from WSDL: {client._address}")
    print(f"add(8, 9) = {client.call('add', a=8, b=9)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: from_file_client.py <path-to-wsdl>")
    main(sys.argv[1])
