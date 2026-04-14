"""XSD complexType inputs and outputs — User { name, email, age }.

Operations whose parameters are richer than the built-in primitives must
declare them via ``OperationParameter(name, ComplexXsdType(...))`` so the
generated WSDL describes the structure and the serializer knows how to map
nested dicts onto child elements.

Run:
    uv add fastapi uvicorn
    uv run python examples/10_complex_types/server.py
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.core.binding import OperationParameter
from soapbar.core.types import ComplexXsdType, xsd
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


# Reusable XSD types
_string = xsd.resolve("string")
_int = xsd.resolve("int")
assert _string is not None and _int is not None

USER_TYPE = ComplexXsdType(
    name="User",
    fields=[
        ("name", _string),
        ("email", _string),
        ("age", _int),
    ],
)


class UserService(SoapService):
    __service_name__ = "UserService"
    __tns__ = "http://example.com/users"

    @soap_operation(
        input_params=[OperationParameter("user", USER_TYPE)],
        output_params=[OperationParameter("user", USER_TYPE)],
    )
    def create_user(self, user: dict) -> dict:
        # Server-side normalisation: lower-case the email, bump the age.
        return {
            "name":  user.get("name", ""),
            "email": (user.get("email") or "").lower(),
            "age":   int(user.get("age") or 0) + 1,
        }


soap_app = SoapApplication(service_url="http://127.0.0.1:8010/soap")
soap_app.register(UserService())

app = FastAPI(title="soapbar — complex types demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8010)
