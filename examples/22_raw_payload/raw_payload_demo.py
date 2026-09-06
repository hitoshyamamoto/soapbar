"""Transport an already-signed XML document without altering a byte.

Regulated schemas (fiscal documents, healthcare messages, anything carrying
an enveloped XML-DSIG signature) are built and signed by the caller; the SOAP
layer's only job is to deliver them untouched. ``RawXmlType`` inserts the
payload into the envelope without parsing or re-serializing it, so the bytes
a signature was computed over arrive exactly as signed — comments,
processing instructions, quoting and all.

This demo runs offline: it captures the wire body with a stub transport and
shows the payload surviving byte-for-byte.

Run:
    uv run python examples/22_raw_payload/raw_payload_demo.py
"""
from __future__ import annotations

from soapbar import HttpTransport, RawXmlType, SoapClient
from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
)

SERVICE_NS = "http://example.com/delivery"

# A payload the caller owns: default namespace, a mixed-case Id (signature
# targets are case-sensitive), a comment, and accented text.
PAYLOAD = (
    b'<Document xmlns="http://example.com/doc" Id="Doc-001">'
    b"<!-- assinado externamente -->"
    b"<emitente>Ind\xc3\xbastria S\xc3\xa3o Paulo Ltda</emitente>"
    b"<valor>123.45</valor>"
    b"</Document>"
)


class _EchoTransport(HttpTransport):
    """Stub transport: captures the request and answers an empty envelope."""

    def __init__(self) -> None:
        super().__init__()
        self.last_body = b""

    def send(self, url, body, headers):
        self.last_body = body
        resp = (
            b'<?xml version="1.0"?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body/></soapenv:Envelope>"
        )
        return 200, "text/xml", resp


def main() -> None:
    transport = _EchoTransport()
    client = SoapClient.manual(
        "https://example.com/soap",
        transport=transport,
        binding_style=BindingStyle.DOCUMENT_LITERAL,
    )
    client.register_operation(OperationSignature(
        name="Deliver",
        input_params=[OperationParameter("documentMsg", RawXmlType(), namespace=SERVICE_NS)],
        soap_action="Deliver",
    ))

    client.call("Deliver", documentMsg=PAYLOAD)

    print("wire body:")
    print(transport.last_body.decode())
    print()
    verbatim = PAYLOAD in transport.last_body
    print(f"payload bytes survived verbatim: {verbatim}")
    assert verbatim


if __name__ == "__main__":
    main()
