"""XML Encryption — encrypt and decrypt the SOAP Body content.

soapbar implements the WSS hybrid scheme:

- AES-256-CBC for the bulk Body content.
- RSA-OAEP (SHA-256) wraps the per-message AES session key with the
  recipient's public key.

The output replaces the original Body children with a single
``<xenc:EncryptedData>`` element.  ``decrypt_body`` reverses the process
using the recipient's private key.

This script generates an ephemeral RSA key pair so it runs with no inputs;
**never reuse this key in production**.

Run:
    uv sync --group dev
    uv run python examples/15_xml_encryption/encrypt_and_decrypt.py
"""
from __future__ import annotations

from lxml import etree

from soapbar.core.envelope import SoapEnvelope, SoapVersion
from soapbar.core.wssecurity import decrypt_body, encrypt_body

XENC_NS = "http://www.w3.org/2001/04/xmlenc#"


def _ephemeral_keypair() -> tuple[object, object]:
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _build_envelope() -> bytes:
    env = SoapEnvelope(version=SoapVersion.SOAP_11)
    body_elem = etree.Element("{http://example.com/secret}Reveal")
    etree.SubElement(body_elem, "{http://example.com/secret}msg").text = "the eagle has landed"
    env.add_body_content(body_elem)
    return env.to_bytes()


def main() -> None:
    print("XML Encryption demo (AES-256-CBC + RSA-OAEP-SHA256)")
    print("-" * 55)

    private_key, public_key = _ephemeral_keypair()
    plaintext = _build_envelope()

    print("Body BEFORE encryption (extract):")
    print("  ", etree.fromstring(plaintext).find(
        "{http://schemas.xmlsoap.org/soap/envelope/}Body"
    )[0][0].text)

    cipher = encrypt_body(plaintext, recipient_public_key=public_key)

    enc_data = etree.fromstring(cipher).find(f".//{{{XENC_NS}}}EncryptedData")
    method = enc_data.find(f"{{{XENC_NS}}}EncryptionMethod").get("Algorithm")
    print(f"\n<xenc:EncryptedData> Algorithm = {method}")
    print(f"ciphertext envelope length     = {len(cipher)} bytes")
    print(f"original Body element gone?    = "
          f"{etree.fromstring(cipher).find('.//{http://example.com/secret}msg') is None}")

    recovered = decrypt_body(cipher, private_key=private_key)
    print("\nBody AFTER decryption (extract):")
    print("  ", etree.fromstring(recovered).find(
        "{http://schemas.xmlsoap.org/soap/envelope/}Body"
    )[0][0].text)

    # Tamper with one base64 character of the ciphertext and confirm the
    # recipient detects it.  AES-CBC alone has no integrity check, but
    # OAEP-wrapped key + PKCS7 padding mismatches surface as decryption
    # errors here.
    cv_tag = f"{{{XENC_NS}}}CipherValue"
    tampered_root = etree.fromstring(cipher)
    cv = tampered_root.findall(f".//{cv_tag}")[-1]
    cv.text = ("A" if cv.text[0] != "A" else "B") + cv.text[1:]
    tampered = etree.tostring(tampered_root, xml_declaration=True, encoding="utf-8")

    try:
        decrypt_body(tampered, private_key=private_key)
    except Exception as exc:  # noqa: BLE001 — any failure here is the point
        print(f"\ntampered ciphertext rejected: {type(exc).__name__}")


if __name__ == "__main__":
    main()
