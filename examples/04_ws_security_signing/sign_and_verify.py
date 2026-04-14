"""S04 / S05 — sign and verify a SOAP envelope (WS-I BSP 1.1 profile).

Demonstrates the v0.5.3 WS-Security signing fixes end-to-end:

* Exclusive XML Canonicalization 1.0 on ``ds:SignedInfo`` and every
  ``ds:Transforms`` (S05 — WS-I BSP R5404).
* An explicit ``ds:Reference`` list covering the Body (and the Timestamp when
  present) so the two elements receive discrete integrity coverage
  (S04 — WS-I BSP R5416 / R5441).

An ephemeral self-signed RSA key pair is generated for the demo so the script
can run with no external inputs.  **Never re-use this key in production.**

Run:
    uv sync --group dev            # installs cryptography + signxml
    uv run python examples/04_ws_security_signing/sign_and_verify.py
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from lxml import etree

from soapbar.core.envelope import SoapEnvelope, SoapVersion
from soapbar.core.namespaces import NS
from soapbar.core.wssecurity import (
    UsernameTokenCredential,
    build_security_header,
    sign_envelope_bsp,
    verify_envelope_bsp,
)

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
EXC_C14N_URI = "http://www.w3.org/2001/10/xml-exc-c14n#"


def _ephemeral_keypair() -> tuple[object, object]:
    """Return (private_key, self_signed_certificate) for demo use only."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "soapbar-demo")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_unsigned_envelope_with_timestamp() -> bytes:
    """Construct a SOAP 1.1 envelope carrying a wsse:Security / wsu:Timestamp."""
    env = SoapEnvelope(version=SoapVersion.SOAP_11)

    # Timestamps ride inside the Security header; build_security_header can
    # create one for us if we pass a UsernameTokenCredential.  We don't want
    # the UsernameToken itself in a signed-only demo, so strip it.
    sec = build_security_header(
        UsernameTokenCredential(username="ignored", password="ignored"),
        soap_ns=SoapVersion.SOAP_11.envelope_ns,
        timestamp_ttl=300,
    )
    for ut in sec.findall(f"{{{NS.WSSE}}}UsernameToken"):
        sec.remove(ut)
    env.add_header(sec)

    # Minimal body payload.
    body = etree.Element("{http://example.com/calc}Ping")
    etree.SubElement(body, "{http://example.com/calc}Msg").text = "hello"
    env.add_body_content(body)

    return env.to_bytes()


def _print_signature_summary(signed: bytes) -> None:
    root = etree.fromstring(signed)
    sig = root.find(f".//{{{DS_NS}}}Signature")
    assert sig is not None, "no ds:Signature emitted"

    c14n_method = sig.find(f".//{{{DS_NS}}}SignedInfo/{{{DS_NS}}}CanonicalizationMethod")
    algo = c14n_method.get("Algorithm") if c14n_method is not None else "<missing>"
    references = sig.findall(f".//{{{DS_NS}}}Reference")

    print(f"  CanonicalizationMethod = {algo}")
    print(f"  exclusive C14N?        = {algo == EXC_C14N_URI}")
    print(f"  ds:Reference count     = {len(references)}")
    for r in references:
        print(f"    Reference URI        = {r.get('URI')!r}")


def main() -> None:
    print("soapbar WS-Security signing demo (WS-I BSP 1.1)")
    print("-" * 55)

    private_key, cert = _ephemeral_keypair()

    unsigned = _build_unsigned_envelope_with_timestamp()
    signed = sign_envelope_bsp(unsigned, private_key=private_key, certificate=cert)

    print("Signed envelope summary:")
    _print_signature_summary(signed)

    # Round-trip verification uses the embedded BinarySecurityToken, so no
    # caller-provided certificate is required.  ``expected_references=2``
    # pins the Reference count at verify time: an attacker who strips the
    # Timestamp reference (signature-wrapping) will fail this check even if
    # the remaining signature is cryptographically valid.
    verify_envelope_bsp(signed, expected_references=2)
    print("\nverify_envelope_bsp() succeeded — signature is intact.")

    # Tamper with the Body and confirm verification fails.
    tampered = signed.replace(b"hello", b"HELLO")
    try:
        verify_envelope_bsp(tampered, expected_references=2)
    except Exception as exc:  # noqa: BLE001 — demo: any error proves the point
        print(f"tampered envelope correctly rejected: {type(exc).__name__}")
    else:
        raise AssertionError("tampered envelope unexpectedly verified")


if __name__ == "__main__":
    main()
