"""MTOM/XOP — package binary attachments alongside a SOAP envelope.

MTOM (Message Transmission Optimization Mechanism) sends binary payloads as
separate MIME parts and references them from the SOAP body via
``<xop:Include href="cid:..."/>``.  This avoids base64 inflation for large
binaries while keeping the SOAP body strictly XML.

This demo is self-contained and shows both directions:

1. Hand-build a SOAP body with an ``xop:Include`` placeholder.
2. ``build_mtom`` packages it with the binary attachment into a
   ``multipart/related`` HTTP body.
3. ``parse_mtom`` decodes the wire format back, resolving every
   ``xop:Include`` so the final ``soap_xml`` is plain XML again.

Run:
    uv run python examples/07_mtom_attachments/build_and_parse.py
"""
from __future__ import annotations

from soapbar.core.mtom import MtomAttachment, build_mtom, parse_mtom
from soapbar.core.namespaces import NS

# A SOAP envelope whose <data> element will be filled in from the MIME
# part with Content-ID "image-1@soapbar".
SOAP_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
    b' xmlns:xop="' + NS.XOP.encode() + b'">'
    b'<soapenv:Body>'
    b'<Upload xmlns="http://example.com/files">'
    b'  <name>logo.png</name>'
    b'  <data><xop:Include href="cid:image-1@soapbar"/></data>'
    b'</Upload>'
    b'</soapenv:Body>'
    b'</soapenv:Envelope>'
)

# 4 bytes pretending to be a real binary file.
PNG_BYTES = b"\x89PNG\r\n\x1a\n"


def main() -> None:
    print("MTOM/XOP build + parse round-trip")
    print("-" * 40)

    attachments = [
        MtomAttachment(
            content_id="image-1@soapbar",
            content_type="image/png",
            data=PNG_BYTES,
        ),
    ]

    body, content_type = build_mtom(SOAP_XML, attachments)
    print(f"Outer Content-Type:\n  {content_type}\n")
    print(f"Body size: {len(body)} bytes "
          f"(SOAP: {len(SOAP_XML)} + binary: {len(PNG_BYTES)})\n")

    print("First 240 bytes of the multipart body:")
    print(body[:240].decode(errors="replace"))
    print("...\n")

    parsed = parse_mtom(body, content_type)
    print(f"parse_mtom recovered {len(parsed.attachments)} attachment(s).")
    print(f"  attachment[0].content_id   = {parsed.attachments[0].content_id}")
    print(f"  attachment[0].content_type = {parsed.attachments[0].content_type}")
    print(f"  attachment[0].data         = {parsed.attachments[0].data!r}")
    print()
    print("Resolved SOAP body (xop:Include replaced with base64):")
    print(parsed.soap_xml.decode())

    # Round-trip integrity check.
    assert parsed.attachments[0].data == PNG_BYTES
    assert b"xop:Include" not in parsed.soap_xml


if __name__ == "__main__":
    main()
