"""WSS UsernameToken authentication (PasswordDigest).

Shows:

* A ``UsernameTokenValidator`` subclass that looks credentials up in a static
  dict.  ``get_password`` is the only method a subclass needs to implement;
  the base class handles PasswordDigest verification, timestamp expiry (N05),
  and nonce-replay caching (N07).
* The S08 gate: this server binds to ``http://`` and therefore sets
  ``allow_plaintext_credentials=True`` — without that flag, the server would
  refuse any UsernameToken whose password uses the plaintext profile.  In
  production, bind to ``https://`` and leave the flag off.

Run:
    uv add fastapi uvicorn
    uv run python examples/06_username_token_auth/server.py
"""
from __future__ import annotations

from fastapi import FastAPI

from soapbar.core.wssecurity import UsernameTokenValidator
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation


_USERS = {"alice": "wonderland", "bob": "builder"}


class StaticValidator(UsernameTokenValidator):
    def get_password(self, username: str) -> str | None:
        return _USERS.get(username)


class Greeter(SoapService):
    __service_name__ = "Greeter"
    __tns__ = "http://example.com/greeter"

    @soap_operation()
    def hello(self, who: str) -> str:
        return f"Hello, {who}!"


soap_app = SoapApplication(
    service_url="http://127.0.0.1:8006/soap",
    security_validator=StaticValidator(),
    # Required because this example runs over plain HTTP.  Drop this flag in
    # production and serve over HTTPS — the server will then reject
    # PasswordText credentials per WSS 1.0 §6.2 (S08).
    allow_plaintext_credentials=True,
)
soap_app.register(Greeter())

app = FastAPI(title="soapbar — WSS UsernameToken demo")
app.mount("/soap", AsgiSoapApp(soap_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8006)
