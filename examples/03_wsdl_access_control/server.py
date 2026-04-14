"""X06 — protect the WSDL behind a shared-secret bearer token.

By default ``?wsdl`` is publicly readable (contract discovery is usually a
feature).  For services where the WSDL is considered sensitive, pass
``wsdl_access="authenticated"`` plus a ``wsdl_auth_hook`` that inspects the
request headers.

In this demo the hook checks the HTTP ``Authorization`` header for a fixed
bearer token.  Real deployments should validate a JWT, session cookie, etc.

Run:
    uv add fastapi uvicorn
    uv run python examples/03_wsdl_access_control/server.py

Then try:
    curl -i http://127.0.0.1:8003/soap?wsdl                              # 403
    curl -i -H 'Authorization: Bearer s3cret' \\
         http://127.0.0.1:8003/soap?wsdl                                  # 200
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


_SECRET = "s3cret"  # noqa: S105 — demo value; never hard-code secrets in production.


def bearer_auth(headers: dict[str, str]) -> bool:
    """Accept requests carrying ``Authorization: Bearer <_SECRET>``."""
    return headers.get("authorization", "") == f"Bearer {_SECRET}"


class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b


soap_app = SoapApplication(
    service_url="http://127.0.0.1:8003/soap",
    wsdl_access="authenticated",
    wsdl_auth_hook=bearer_auth,
)
soap_app.register(Calculator())

app = FastAPI(title="soapbar — protected WSDL demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8003)
