"""Parse a hand-written SOAP envelope and inspect its parsed properties.

Demonstrates the read-only side of ``SoapEnvelope`` — useful when writing
intermediaries, monitoring tools, or test fixtures that need to look at an
envelope without dispatching it.

Run:
    uv run python examples/16_introspection/inspect_envelope.py
"""
from __future__ import annotations

from soapbar.core.envelope import SoapEnvelope

ENVELOPE = b"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <soapenv:Header>
    <wsa:MessageID>urn:uuid:11111111-2222-3333-4444-555555555555</wsa:MessageID>
    <wsa:To>http://example.com/calc</wsa:To>
    <wsa:Action>http://example.com/calc/Add</wsa:Action>
    <wsa:ReplyTo>
      <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>
    </wsa:ReplyTo>
  </soapenv:Header>
  <soapenv:Body>
    <Add xmlns="http://example.com/calc">
      <a>3</a>
      <b>4</b>
    </Add>
  </soapenv:Body>
</soapenv:Envelope>
"""

FAULT = b"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>soapenv:Client</faultcode>
      <faultstring>Bad request</faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>
"""


def inspect(label: str, raw: bytes) -> None:
    env = SoapEnvelope.from_xml(raw)
    print(f"=== {label} ===")
    print(f"  version            = {env.version.value}")
    print(f"  is_fault           = {env.is_fault}")
    print(f"  operation_name     = {env.operation_name}")
    print(f"  operation_namespace= {env.operation_namespace}")
    if env.ws_addressing is not None:
        print(f"  wsa.message_id     = {env.ws_addressing.message_id}")
        print(f"  wsa.action         = {env.ws_addressing.action}")
        print(f"  wsa.to             = {env.ws_addressing.to}")
        if env.ws_addressing.reply_to is not None:
            print(f"  wsa.reply_to       = {env.ws_addressing.reply_to.address}")
    if env.is_fault:
        f = env.fault
        print(f"  fault.code/str     = {f.faultcode!r} / {f.faultstring!r}")
    print()


def main() -> None:
    inspect("Request envelope (with WS-Addressing)", ENVELOPE)
    inspect("Fault envelope", FAULT)


if __name__ == "__main__":
    main()
