"""Targeted tests for under-covered error/parse branches in the security and
parsing modules (wssecurity, fault, mtom).

These exercise failure and edge paths that the happy-path suite does not reach,
widening the margin above the coverage gate and — more importantly — pinning
the behaviour of the security-relevant branches (uniform decryption errors,
malformed-fault handling).
"""
from __future__ import annotations

from typing import Any

import pytest
from lxml import etree

from soapbar import SoapFault, XmlSecurityError, decrypt_body, encrypt_body, extract_xop_elements
from soapbar.core.namespaces import NS

_XENC_NS = "http://www.w3.org/2001/04/xmlenc#"


# ---------------------------------------------------------------------------
# mtom.extract_xop_elements
# ---------------------------------------------------------------------------
def test_extract_xop_elements_returns_parent_tag() -> None:
    xml = (
        f'<Data xmlns:xop="{NS.XOP}">'
        f'<image><xop:Include href="cid:img1"/></image>'
        f"</Data>"
    ).encode()
    found = extract_xop_elements(xml)
    assert len(found) == 1
    parent_tag, elem = found[0]
    assert parent_tag.endswith("image")
    assert elem.get("href") == "cid:img1"


def test_extract_xop_elements_root_include_has_empty_parent_tag() -> None:
    # An <xop:Include> that is itself the document root has no parent element,
    # so the reported parent tag is empty.
    xml = f'<xop:Include xmlns:xop="{NS.XOP}" href="cid:only"/>'.encode()
    found = extract_xop_elements(xml)
    assert len(found) == 1
    assert found[0][0] == ""


def test_extract_xop_elements_empty_when_no_includes() -> None:
    assert extract_xop_elements(b"<Data><image/></Data>") == []


# ---------------------------------------------------------------------------
# fault.SoapFault.from_element — malformed / edge inputs
# ---------------------------------------------------------------------------
def test_from_element_envelope_without_fault_raises() -> None:
    env = etree.fromstring(
        f'<soap:Envelope xmlns:soap="{NS.SOAP_ENV}"><soap:Body/></soap:Envelope>'.encode()
    )
    with pytest.raises(ValueError, match="No Fault element found"):
        SoapFault.from_element(env)


def test_from_element_unrelated_element_raises() -> None:
    with pytest.raises(ValueError, match="Cannot parse fault"):
        SoapFault.from_element(etree.fromstring(b"<foo/>"))


def test_from_element_soap12_fault_missing_code_and_reason() -> None:
    # Direct SOAP 1.2 Fault element (not wrapped in an Envelope) with neither a
    # Code nor a Reason child: both default to empty rather than raising.
    fault = etree.fromstring(
        f'<soap:Fault xmlns:soap="{NS.SOAP12_ENV}"/>'.encode()
    )
    parsed = SoapFault.from_element(fault)
    assert parsed.faultcode == ""
    assert parsed.faultstring == ""


def test_from_element_soap12_fault_empty_code_and_reason() -> None:
    # Code present but no Value, Reason present but no Text.
    fault = etree.fromstring(
        f'<soap:Fault xmlns:soap="{NS.SOAP12_ENV}">'
        f"<soap:Code/><soap:Reason/>"
        f"</soap:Fault>".encode()
    )
    parsed = SoapFault.from_element(fault)
    assert parsed.faultcode == ""
    assert parsed.faultstring == ""


def test_from_element_soap12_fault_detail_with_child_element() -> None:
    fault = etree.fromstring(
        f'<soap:Fault xmlns:soap="{NS.SOAP12_ENV}">'
        f"<soap:Code><soap:Value>soap:Receiver</soap:Value></soap:Code>"
        f"<soap:Reason><soap:Text>boom</soap:Text></soap:Reason>"
        f"<soap:Detail><myErr>x</myErr></soap:Detail>"
        f"</soap:Fault>".encode()
    )
    parsed = SoapFault.from_element(fault)
    assert parsed.faultcode == "Server"  # Receiver → Server
    assert parsed.faultstring == "boom"
    assert parsed.detail is not None
    # detail is the child element, not text
    assert not isinstance(parsed.detail, str)


# ---------------------------------------------------------------------------
# wssecurity.decrypt_body — error branches
# ---------------------------------------------------------------------------
crypto = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

_ENVELOPE = (
    f'<soap:Envelope xmlns:soap="{NS.SOAP_ENV}">'
    f"<soap:Body><Ping>hello</Ping></soap:Body>"
    f"</soap:Envelope>"
).encode()


@pytest.fixture(scope="module")
def rsa_keypair() -> tuple[Any, Any]:  # type: ignore[valid-type]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _encrypted(rsa_keypair: tuple[Any, Any]) -> Any:  # type: ignore[valid-type]
    _, public = rsa_keypair
    return etree.fromstring(encrypt_body(_ENVELOPE, public))


def test_encrypt_decrypt_roundtrip(rsa_keypair: tuple[Any, Any]) -> None:  # type: ignore[valid-type]
    private, public = rsa_keypair
    enc = encrypt_body(_ENVELOPE, public)
    assert b"EncryptedData" in enc
    dec = decrypt_body(enc, private)
    assert b"<Ping>hello</Ping>" in dec


def test_decrypt_defaults_to_gcm_when_encryption_method_absent(
    rsa_keypair: tuple[Any, Any],  # type: ignore[valid-type]
) -> None:
    # Removing the EncryptionMethod element must not break decryption: the
    # algorithm defaults to AES-256-GCM (the value encrypt_body produced).
    private, _ = rsa_keypair
    root = _encrypted(rsa_keypair)
    enc_data = root.find(f".//{{{_XENC_NS}}}EncryptedData")
    method = enc_data.find(f"{{{_XENC_NS}}}EncryptionMethod")
    enc_data.remove(method)
    dec = decrypt_body(etree.tostring(root), private)
    assert b"<Ping>hello</Ping>" in dec


def test_decrypt_unsupported_algorithm_raises(rsa_keypair: tuple[Any, Any]) -> None:  # type: ignore[valid-type]
    private, _ = rsa_keypair
    root = _encrypted(rsa_keypair)
    method = root.find(f".//{{{_XENC_NS}}}EncryptedData/{{{_XENC_NS}}}EncryptionMethod")
    method.set("Algorithm", "urn:example:rot13")
    with pytest.raises(XmlSecurityError, match="Unsupported encryption algorithm"):
        decrypt_body(etree.tostring(root), private)


def test_decrypt_missing_wrapped_key_raises(rsa_keypair: tuple[Any, Any]) -> None:  # type: ignore[valid-type]
    private, _ = rsa_keypair
    root = _encrypted(rsa_keypair)
    # Drop the CipherValue holding the RSA-wrapped session key.
    cv = root.find(
        f".//{{{_XENC_NS}}}EncryptedKey/{{{_XENC_NS}}}CipherData/{{{_XENC_NS}}}CipherValue"
    )
    cv.getparent().remove(cv)
    with pytest.raises(XmlSecurityError, match="Missing xenc:EncryptedKey"):
        decrypt_body(etree.tostring(root), private)


def test_decrypt_missing_body_ciphervalue_raises(rsa_keypair: tuple[Any, Any]) -> None:  # type: ignore[valid-type]
    private, _ = rsa_keypair
    root = _encrypted(rsa_keypair)
    enc_data = root.find(f".//{{{_XENC_NS}}}EncryptedData")
    # The body CipherData/CipherValue is the EncryptedData's *direct* child,
    # distinct from the one inside EncryptedKey.
    body_cv = enc_data.find(f"{{{_XENC_NS}}}CipherData/{{{_XENC_NS}}}CipherValue")
    body_cv.getparent().remove(body_cv)
    with pytest.raises(XmlSecurityError, match="Missing xenc:CipherData"):
        decrypt_body(etree.tostring(root), private)
