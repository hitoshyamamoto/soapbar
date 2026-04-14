"""SOAP 1.2 client — auto-detects SOAP 1.2 from the WSDL binding.

Run:
    uv run python examples/02_soap12/server.py &
    uv run python examples/02_soap12/client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.core.envelope import SoapVersion


def main() -> None:
    client = SoapClient(wsdl_url="http://127.0.0.1:8012/soap?wsdl")

    # The binding in the WSDL announces SOAP 1.2; SoapClient picks this up.
    assert client._soap_version is SoapVersion.SOAP_12, \
        f"expected SOAP 1.2 binding, got {client._soap_version}"

    print(f"add(2, 5)        = {client.call('add',      a=2, b=5)}")
    print(f"subtract(9, 1)   = {client.call('subtract', a=9, b=1)}")


if __name__ == "__main__":
    main()
