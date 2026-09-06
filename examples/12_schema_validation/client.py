"""Hit the schema-validating server with one valid and one invalid payload.

Run:
    uv run python examples/12_schema_validation/server.py &
    uv run python examples/12_schema_validation/client.py
"""
from __future__ import annotations

import httpx

URL = "http://127.0.0.1:8012/soap"

# The wrapper element is qualified (it is a global element in the target
# namespace) while its children are NOT: the generated schema declares
# elementFormDefault="unqualified", matching soapbar's serializer. A payload
# using a default xmlns (which qualifies the children too) violates the
# published contract and is rejected once validation is on.
VALID = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b'  <soapenv:Body><c:square xmlns:c="http://example.com/calc">'
    b'    <n>9</n>'
    b'  </c:square></soapenv:Body>'
    b'</soapenv:Envelope>'
)

# `n` is declared as xs:int — passing a string the schema can't coerce
# trips xsd validation before the service is called.
INVALID = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b'  <soapenv:Body><c:square xmlns:c="http://example.com/calc">'
    b'    <n>not-a-number</n>'
    b'  </c:square></soapenv:Body>'
    b'</soapenv:Envelope>'
)


def post(label: str, body: bytes) -> None:
    r = httpx.post(URL, content=body, follow_redirects=True, headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '""',
    })
    print(f"--- {label}: HTTP {r.status_code}")
    print(r.text)
    print()


def main() -> None:
    post("valid request", VALID)
    post("schema-invalid request (expect Client fault)", INVALID)


if __name__ == "__main__":
    main()
