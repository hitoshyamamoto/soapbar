"""Client for the complex-types example — sends a User dict, prints the reply.

We use ``SoapClient.manual(...)`` + ``register_operation(...)`` here rather
than ``SoapClient(wsdl_url=...)``.  At the time of writing, the WSDL-driven
auto-registration path drops the ``ComplexXsdType`` binding — the complex
type survives round-tripping only when the signature is registered by hand.
Server-side registration is unaffected.

Run:
    uv run python examples/10_complex_types/server.py &
    uv run python examples/10_complex_types/client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import SoapVersion
from soapbar.core.types import ComplexXsdType, xsd

# Mirror the server's User complex type.  In a real codebase this would live
# in a shared module that both sides import.
_string = xsd.resolve("string")
_int = xsd.resolve("int")
assert _string is not None and _int is not None

USER_TYPE = ComplexXsdType(
    name="User",
    fields=[("name", _string), ("email", _string), ("age", _int)],
)


def main() -> None:
    client = SoapClient.manual(
        address="http://127.0.0.1:8010/soap",
        binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
        soap_version=SoapVersion.SOAP_11,
    )
    client.register_operation(OperationSignature(
        name="create_user",
        input_params=[OperationParameter("user", USER_TYPE)],
        output_params=[OperationParameter("user", USER_TYPE)],
        soap_action="http://example.com/users/create_user",
        input_namespace="http://example.com/users",
        output_namespace="http://example.com/users",
    ))

    sent = {"name": "Ada Lovelace", "email": "Ada@EXAMPLE.com", "age": 36}
    print(f"sent:    {sent}")
    reply = client.call("create_user", user=sent)
    print(f"reply:   {reply}")


if __name__ == "__main__":
    main()
