"""Exercise both response modes against examples/11_one_way_and_json/server.py.

Uses raw httpx for the HTTP-status assertion on the one-way path (SoapClient
expects a SOAP body to parse, which a 202-with-empty-body doesn't provide)
and again for the JSON path so the Accept header is honoured.

Run:
    uv run python examples/11_one_way_and_json/server.py &
    uv run python examples/11_one_way_and_json/client.py
"""
from __future__ import annotations

import httpx

from soapbar.client.client import SoapClient

URL = "http://127.0.0.1:8011/soap"

ONE_WAY_REQUEST = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b'  <soapenv:Body><emit_log xmlns="http://example.com/mixed">'
    b'    <msg>hello from a fire-and-forget call</msg>'
    b'  </emit_log></soapenv:Body>'
    b'</soapenv:Envelope>'
)

ECHO_REQUEST = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b'  <soapenv:Body><echo xmlns="http://example.com/mixed">'
    b'    <msg>hello</msg>'
    b'  </echo></soapenv:Body>'
    b'</soapenv:Envelope>'
)


def main() -> None:
    print("--- 1) Plain SOAP echo via SoapClient (sanity check)")
    client = SoapClient(wsdl_url=f"{URL}?wsdl")
    print(f"  echo('hello') = {client.call('echo', msg='hello')}\n")

    print("--- 2) One-way operation: expect HTTP 202 + empty body")
    r = httpx.post(URL, content=ONE_WAY_REQUEST, headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '""',
    })
    print(f"  HTTP status = {r.status_code}")
    print(f"  body bytes  = {len(r.content)}\n")

    print("--- 3) JSON dual-mode: same SOAP request, Accept: application/json")
    r = httpx.post(URL, content=ECHO_REQUEST, headers={
        "Content-Type": "text/xml; charset=utf-8",
        "Accept": "application/json",
        "SOAPAction": '""',
    })
    print(f"  HTTP status   = {r.status_code}")
    print(f"  Content-Type  = {r.headers.get('content-type')}")
    print(f"  body          = {r.text}")


if __name__ == "__main__":
    main()
