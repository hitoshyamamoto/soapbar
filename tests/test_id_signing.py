"""Conformance tests for sign_element_by_id (Id/Reference-URI targeted signing).

Signs an ``<infNFe>``-like inner element and asserts the produced ds:Signature
matches the requested algorithm set, references the element by ``#Id``, carries
only the end-entity certificate, and verifies. Skipped without signxml.
"""
from __future__ import annotations

import datetime

import pytest

from soapbar.core.wssecurity import XmlSecurityError, sign_element_by_id

pytest.importorskip("signxml")
pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

DS = "http://www.w3.org/2000/09/xmldsig#"
NFE_NS = "http://www.portalfiscal.inf.br/nfe"

# An <infNFe>-like element with an Id, wrapped in <NFe> so the signature lands
# as a sibling of <infNFe> (the NF-e layout).
ID_VALUE = "NFe31060243816719000108550010000000011234567890"
DOC = (
    f'<NFe xmlns="{NFE_NS}">'
    f'<infNFe Id="{ID_VALUE}" versao="4.00"><ide><cUF>31</cUF></ide></infNFe>'
    f"</NFe>"
).encode()


@pytest.fixture(scope="module")
def keypair() -> tuple[rsa.RSAPrivateKey, x509.Certificate, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "soapbar-signing-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key, cert, cert_pem


def _sign(keypair, **kwargs) -> etree._Element:
    key, cert, _ = keypair
    out = sign_element_by_id(DOC, ID_VALUE, key, cert, **kwargs)
    return etree.fromstring(out)


def test_signature_is_sibling_of_target_with_correct_reference(keypair) -> None:
    root = _sign(keypair)
    # ds:Signature is appended to <NFe>, a sibling of <infNFe>.
    sig = root.find(f"{{{DS}}}Signature")
    assert sig is not None
    assert root.find(f"{{{NFE_NS}}}infNFe") is not None

    refs = sig.findall(f".//{{{DS}}}Reference")
    assert len(refs) == 1
    assert refs[0].get("URI") == f"#{ID_VALUE}"


def test_signature_placed_inside_matching_nfe_in_batch(keypair) -> None:
    # In an enviNFe lote the Signature must sit inside the matching <NFe>
    # (sibling of <infNFe>), not at the <enviNFe> root — SEFAZ rejects otherwise.
    key, cert, _ = keypair
    batch = (
        f'<enviNFe xmlns="{NFE_NS}" versao="4.00"><idLote>1</idLote>'
        f'<NFe><infNFe Id="NFe999" versao="4.00"><ide><cUF>31</cUF></ide></infNFe></NFe>'
        f"</enviNFe>"
    ).encode()
    root = etree.fromstring(sign_element_by_id(batch, "NFe999", key, cert))
    sig = root.find(f".//{{{DS}}}Signature")
    assert sig is not None
    parent = sig.getparent()
    assert etree.QName(parent).localname == "NFe"  # inside the NFe, not enviNFe
    assert parent.find(f"{{{NFE_NS}}}infNFe") is not None  # truly a sibling of infNFe


def test_nfe_algorithm_set(keypair) -> None:
    root = _sign(keypair, signature_method="rsa-sha1", digest_method="sha1", c14n="inclusive")
    sig = root.find(f"{{{DS}}}Signature")
    signed_info = sig.find(f"{{{DS}}}SignedInfo")

    assert signed_info.find(f"{{{DS}}}CanonicalizationMethod").get("Algorithm") == (
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )
    assert signed_info.find(f"{{{DS}}}SignatureMethod").get("Algorithm") == (
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    )
    reference = signed_info.find(f"{{{DS}}}Reference")
    assert reference.find(f"{{{DS}}}DigestMethod").get("Algorithm") == (
        "http://www.w3.org/2000/09/xmldsig#sha1"
    )
    transforms = [
        t.get("Algorithm") for t in reference.findall(f"{{{DS}}}Transforms/{{{DS}}}Transform")
    ]
    assert "http://www.w3.org/2000/09/xmldsig#enveloped-signature" in transforms


def test_default_algorithm_set_is_sha256(keypair) -> None:
    root = _sign(keypair)  # defaults
    signed_info = root.find(f"{{{DS}}}Signature/{{{DS}}}SignedInfo")
    assert signed_info.find(f"{{{DS}}}SignatureMethod").get("Algorithm").endswith("rsa-sha256")
    assert signed_info.find(f"{{{DS}}}Reference/{{{DS}}}DigestMethod").get(
        "Algorithm"
    ).endswith("sha256")


def test_key_info_end_entity_only(keypair) -> None:
    root = _sign(keypair, end_cert_only=True)
    key_info = root.find(f"{{{DS}}}Signature/{{{DS}}}KeyInfo")
    assert key_info is not None
    assert len(key_info.findall(f".//{{{DS}}}X509Certificate")) == 1
    # No RSA KeyValue when only the end-entity cert is wanted.
    assert key_info.find(f".//{{{DS}}}KeyValue") is None


def test_end_cert_only_false_adds_key_value(keypair) -> None:
    root = _sign(keypair, end_cert_only=False)
    key_info = root.find(f"{{{DS}}}Signature/{{{DS}}}KeyInfo")
    assert key_info.find(f".//{{{DS}}}KeyValue") is not None


def test_signature_verifies(keypair) -> None:
    from signxml import XMLVerifier

    key, cert, cert_pem = keypair
    # Default (SHA-256) set so signxml's verifier accepts it; this proves the
    # digest is computed over the canonicalized target element.
    signed = sign_element_by_id(DOC, ID_VALUE, key, cert)
    XMLVerifier().verify(signed, x509_cert=cert_pem.decode(), id_attribute="Id")


def test_rejects_unsupported_algorithm(keypair) -> None:
    key, cert, _ = keypair
    with pytest.raises(ValueError, match="signature_method"):
        sign_element_by_id(DOC, ID_VALUE, key, cert, signature_method="rsa-md5")
    with pytest.raises(ValueError, match="digest_method"):
        sign_element_by_id(DOC, ID_VALUE, key, cert, digest_method="md5")
    with pytest.raises(ValueError, match="c14n"):
        sign_element_by_id(DOC, ID_VALUE, key, cert, c14n="nope")


def test_missing_id_raises_security_error(keypair) -> None:
    key, cert, _ = keypair
    with pytest.raises(XmlSecurityError):
        sign_element_by_id(DOC, "NoSuchId", key, cert)
