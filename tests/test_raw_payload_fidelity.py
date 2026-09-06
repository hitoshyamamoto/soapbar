"""Byte-fidelity suite for RawXmlType — pre-built XML payload passthrough.

The central invariant is NOT "sent without error". It is:

    c14n(original_payload) == c14n(fragment_extracted_from_the_wire)

checked under BOTH inclusive and exclusive canonicalization, plus a literal
byte-substring check on the wire body — because XML-DSIG signs canonical
bytes, and a transport that re-serializes a signed payload invalidates the
signature. The end-to-end proof is a real signature: sign with signxml
(inclusive C14N, the NF-e profile), send through SoapClient, extract the
fragment from the captured wire bytes, verify.
"""

from __future__ import annotations

import pytest
from lxml import etree

from soapbar import HttpTransport, SoapClient
from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
)
from soapbar.core.types import RawXmlType

_NS = "http://example.com/payload"

_RESPONSE = (
    b'<?xml version="1.0"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<soapenv:Body/></soapenv:Envelope>"
)


class _CapturingTransport(HttpTransport):
    def __init__(self, response: bytes = _RESPONSE, content_type: str = "text/xml") -> None:
        super().__init__()
        self.last_body: bytes = b""
        self._response = response
        self._content_type = content_type

    def send(self, url, body, headers):
        self.last_body = body
        return 200, self._content_type, self._response


def _client(
    style: BindingStyle = BindingStyle.DOCUMENT_LITERAL,
    response: bytes = _RESPONSE,
) -> tuple[SoapClient, _CapturingTransport]:
    transport = _CapturingTransport(response=response)
    client = SoapClient.manual(
        "https://example.com/soap", transport=transport, binding_style=style
    )
    client.register_operation(OperationSignature(
        name="Deliver",
        input_params=[OperationParameter("payloadMsg", RawXmlType(), namespace=_NS)],
        soap_action="Deliver",
    ))
    return client, transport


def _extract_fragment(wire: bytes, local_name: str) -> bytes:
    """Locate the payload's root element inside the wire bytes and return the
    exact byte slice — no re-parse, no re-serialization. The payload rides as
    the carrier's child, so its start tag and matching end tag (or />) bound
    it; fidelity of this slice is exactly what a signature verifier sees."""
    import re

    name = re.escape(local_name.encode())
    start_m = re.search(rb"<(?:[A-Za-z0-9_.-]+:)?" + name + rb"[\s>/]", wire)
    assert start_m is not None, f"payload root <{local_name}> not found in wire body"
    start = start_m.start()
    end_m = None
    for m in re.finditer(rb"</(?:[A-Za-z0-9_.-]+:)?" + name + rb">", wire):
        end_m = m
    if end_m is not None:
        return wire[start:end_m.end()]
    # self-closing form
    close = wire.find(b"/>", start)
    assert close != -1
    return wire[start:close + 2]


def _c14n(data: bytes, exclusive: bool) -> bytes:
    parsed = etree.fromstring(data)
    return etree.tostring(parsed, method="c14n", exclusive=exclusive)


def _assert_fidelity(original: bytes, wire: bytes, local_name: str) -> None:
    assert original in wire, "payload bytes are not a verbatim substring of the wire body"
    fragment = _extract_fragment(wire, local_name)
    for exclusive in (False, True):
        assert _c14n(original, exclusive) == _c14n(fragment, exclusive), (
            f"c14n (exclusive={exclusive}) differs between original and wire fragment"
        )


# ---------------------------------------------------------------------------
# Fidelity vectors — the places where re-serializers fail
# ---------------------------------------------------------------------------


PAYLOADS = {
    "default_ns": b'<NFe xmlns="http://x.example/nfe"><infNFe Id="NFe1"><v>1</v></infNFe></NFe>',
    "prefixed": b'<p:Doc xmlns:p="http://x.example/p"><p:a>1</p:a></p:Doc>',
    "inner_xmlns": b'<Doc xmlns="http://x.example/d"><part xmlns="http://x.example/inner"><q>2</q></part></Doc>',
    "id_case": b'<Doc xmlns="http://x.example/d" Id="MiXeDcAsE-01"><a>1</a></Doc>',
    "foreign_signature": (
        b'<Doc xmlns="http://x.example/d"><a>1</a>'
        b'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/></Signature></Doc>'
    ),
    "accents": "<Doc xmlns=\"http://x.example/d\"><nome>São Paulo Ltda ç</nome></Doc>".encode(),
    "comments_and_pi": (
        b'<Doc xmlns="http://x.example/d"><!-- keep me --><?pi data?><a>1</a></Doc>'
    ),
    "cdata": b'<Doc xmlns="http://x.example/d"><a><![CDATA[<not-xml> & raw]]></a></Doc>',
}


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_request_fidelity_document_literal_bare(name: str) -> None:
    payload = PAYLOADS[name]
    client, transport = _client(BindingStyle.DOCUMENT_LITERAL)
    client.call("Deliver", payloadMsg=payload)
    local = payload.split(b" ", 1)[0].split(b">", 1)[0].lstrip(b"<").split(b":")[-1]
    _assert_fidelity(payload, transport.last_body, local.decode())


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_request_fidelity_document_literal_wrapped(name: str) -> None:
    payload = PAYLOADS[name]
    client, transport = _client(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
    client.call("Deliver", payloadMsg=payload)
    local = payload.split(b" ", 1)[0].split(b">", 1)[0].lstrip(b"<").split(b":")[-1]
    _assert_fidelity(payload, transport.last_body, local.decode())


def test_large_payload_round_trips_untouched() -> None:
    """~2 MB payload: byte-substring fidelity and no reprocessing blowup."""
    blob = b"<row>" + b"x" * 100 + b"</row>"
    payload = (
        b'<Doc xmlns="http://x.example/d">' + blob * 20_000 + b"</Doc>"
    )
    client, transport = _client()
    client.call("Deliver", payloadMsg=payload)
    assert payload in transport.last_body


def test_str_and_element_inputs_normalize_once() -> None:
    """str encodes to UTF-8; an lxml Element is serialized exactly once
    (fixing the bytes(_Element) TypeError AnyXmlType raises today)."""
    payload_str = '<Doc xmlns="http://x.example/d"><nome>ç</nome></Doc>'
    client, transport = _client()
    client.call("Deliver", payloadMsg=payload_str)
    assert payload_str.encode("utf-8") in transport.last_body

    elem = etree.fromstring(b'<Doc xmlns="http://x.example/d"><a>1</a></Doc>')
    expected = etree.tostring(elem)
    client2, transport2 = _client()
    client2.call("Deliver", payloadMsg=elem)
    assert expected in transport2.last_body


def test_encoded_styles_refuse_raw_passthrough() -> None:
    """RPC/encoded serializers would XML-escape the payload into text; that
    silent corruption is refused loudly instead."""
    client, _transport = _client(BindingStyle.RPC_ENCODED)
    with pytest.raises(ValueError, match="RawXmlType"):
        client.call("Deliver", payloadMsg=b"<Doc xmlns='http://x'/>")


# ---------------------------------------------------------------------------
# Response side: RawXmlType output returns the element's bytes
# ---------------------------------------------------------------------------


def test_raw_output_returns_response_fragment() -> None:
    inner = (
        b'<retConsStatServ xmlns="http://x.example/nfe" versao="4.00">'
        b"<cStat>107</cStat></retConsStatServ>"
    )
    response = (
        b'<?xml version="1.0"?>'
        b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        b'<soapenv:Body><resultMsg xmlns="' + _NS.encode() + b'">' + inner + b"</resultMsg>"
        b"</soapenv:Body></soapenv:Envelope>"
    )
    transport = _CapturingTransport(response=response)
    client = SoapClient.manual(
        "https://example.com/soap",
        transport=transport,
        binding_style=BindingStyle.DOCUMENT_LITERAL,
    )
    client.register_operation(OperationSignature(
        name="Query",
        input_params=[OperationParameter("payloadMsg", RawXmlType(), namespace=_NS)],
        output_params=[OperationParameter("resultMsg", RawXmlType(), namespace=_NS)],
        soap_action="Query",
    ))
    result = client.call("Query", payloadMsg=b'<q xmlns="http://x.example/nfe"/>')
    assert result is not None, "RawXmlType output returned None"
    assert isinstance(result, bytes)
    # Tree-verbatim contract: exclusive c14n equality with the original element.
    got = etree.tostring(etree.fromstring(result), method="c14n", exclusive=True)
    want = etree.tostring(etree.fromstring(
        b'<resultMsg xmlns="' + _NS.encode() + b'">' + inner + b"</resultMsg>"
    ), method="c14n", exclusive=True)
    assert got == want


# ---------------------------------------------------------------------------
# The proof: a real XML-DSIG signature survives the trip
# ---------------------------------------------------------------------------


def test_signed_document_verifies_after_transport() -> None:
    """Generate a self-signed keypair, sign a document with signxml using
    INCLUSIVE C14N (the NF-e profile), send it through SoapClient with
    RawXmlType, extract the fragment from the captured wire bytes, and
    verify the signature. If this verifies, compatibility with
    sign-then-transport toolchains is proven, not argued."""
    signxml = pytest.importorskip("signxml")
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "raw-payload-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    cert_pem = cert.public_bytes(Encoding.PEM)

    doc = etree.fromstring(
        b'<Doc xmlns="http://x.example/d" Id="D1"><valor>123.45</valor></Doc>'
    )
    signed = signxml.XMLSigner(
        method=signxml.methods.enveloped,
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ).sign(doc, key=key_pem, cert=cert_pem)
    signed_bytes = etree.tostring(signed)

    client, transport = _client(BindingStyle.DOCUMENT_LITERAL)
    client.call("Deliver", payloadMsg=signed_bytes)
    assert signed_bytes in transport.last_body, "signed bytes were altered in transit"

    fragment = _extract_fragment(transport.last_body, "Doc")
    verified = signxml.XMLVerifier().verify(
        etree.fromstring(fragment), x509_cert=cert_pem
    )
    assert verified.signed_xml is not None
