"""Build a SoapClient without ever fetching a WSDL.

Useful when the WSDL is unreachable, deliberately undocumented, or unstable
and you want to pin your client behavior to a specific binding & SOAP
version.  You provide the operation signature(s) by hand.

Run (against the calculator from 01_calculator):
    uv run python examples/01_calculator/server_fastapi.py &
    uv run python examples/13_advanced_client/manual_client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import SoapVersion
from soapbar.core.types import xsd

INT = xsd.resolve("int")
assert INT is not None


def main() -> None:
    client = SoapClient.manual(
        address="http://127.0.0.1:8000/soap",
        binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
        soap_version=SoapVersion.SOAP_11,
    )
    client.register_operation(OperationSignature(
        name="add",
        input_params=[OperationParameter("a", INT), OperationParameter("b", INT)],
        output_params=[OperationParameter("result", INT)],
    ))

    print(f"add(11, 22) = {client.call('add', a=11, b=22)}")


if __name__ == "__main__":
    main()
