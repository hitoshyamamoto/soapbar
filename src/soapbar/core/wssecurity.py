"""WS-Security 1.0 support (OASIS WSS 2004).

Implements:
- PasswordText (plain-text password in wsse:Password)
- PasswordDigest (SHA-1 digest per WSS 1.0 §3.2.1)
- XML Digital Signature (XML-DSIG) via signxml ≥ 3.0
- XML Encryption (XMLEnc) via cryptography ≥ 41.0

G09: WS-Security UsernameToken credential building and validation.
I03: XML Signature and XML Encryption.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.xml import make_element, sub_element

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PasswordText = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
)
_PasswordDigest = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
)
_Base64Binary = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)
#: ValueType for WS-I BSP X.509 v3 token (R3029)
_X509V3_VALUETYPE = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-x509-token-profile-1.0#X509v3"
)
#: XML-DSIG namespace (used to locate ds:KeyInfo in signed envelopes)
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------

@dataclass
class UsernameTokenCredential:
    """Holds the username and password for a WS-Security UsernameToken.

    Args:
        username: The username to embed.
        password: The plain-text password.
        use_digest: If True, the password is hashed via PasswordDigest
            (SHA-1 based, per WSS 1.0 §3.2.1).  If False (default),
            PasswordText is used.
        nonce: Override the random nonce bytes (mainly for testing).
        created: Override the creation timestamp string (mainly for testing).
    """
    username: str
    password: str
    use_digest: bool = False
    nonce: bytes | None = field(default=None, repr=False)
    created: str | None = None


# ---------------------------------------------------------------------------
# Digest helper
# ---------------------------------------------------------------------------

def _digest_password(nonce_bytes: bytes, created: str, password: str) -> str:
    """Compute PasswordDigest = Base64(SHA-1(nonce + created + password)).

    Per OASIS WSS UsernameToken Profile 1.0 §3.2.1.
    """
    raw = nonce_bytes + created.encode("utf-8") + password.encode("utf-8")
    return base64.b64encode(hashlib.sha1(raw).digest()).decode("ascii")  # noqa: S324


# ---------------------------------------------------------------------------
# Security header builder
# ---------------------------------------------------------------------------

def build_security_header(
    credential: UsernameTokenCredential,
    soap_ns: str | None = None,
) -> _Element:
    """Build a ``wsse:Security`` header element for *credential*.

    Returns a ``wsse:Security`` element ready to be added as a SOAP header.
    Per WS-Security 1.0 §6.1, the Security header MUST carry
    ``{soap_ns}mustUnderstand="1"`` so intermediaries know to process it.
    Pass *soap_ns* as the SOAP envelope namespace URI to enable this attribute.
    """
    wsse_ns = NS.WSSE
    wsu_ns = NS.WSU
    nsmap: dict[str | None, str] = {"wsse": wsse_ns, "wsu": wsu_ns}

    security = make_element(f"{{{wsse_ns}}}Security", nsmap=nsmap)
    if soap_ns is not None:
        security.set(f"{{{soap_ns}}}mustUnderstand", "1")

    token = sub_element(security, f"{{{wsse_ns}}}UsernameToken")
    sub_element(token, f"{{{wsse_ns}}}Username", text=credential.username)

    if credential.use_digest:
        nonce_bytes = credential.nonce if credential.nonce is not None else secrets.token_bytes(16)
        created = credential.created or datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        digest = _digest_password(nonce_bytes, created, credential.password)

        pw_elem = sub_element(
            token,
            f"{{{wsse_ns}}}Password",
            attrib={"Type": _PasswordDigest},
            text=digest,
        )
        _ = pw_elem  # used via sub_element side-effect

        nonce_elem = sub_element(
            token,
            f"{{{wsse_ns}}}Nonce",
            attrib={"EncodingType": _Base64Binary},
            text=base64.b64encode(nonce_bytes).decode("ascii"),
        )
        _ = nonce_elem

        created_elem = sub_element(token, f"{{{wsu_ns}}}Created", text=created)
        _ = created_elem
    else:
        sub_element(
            token,
            f"{{{wsse_ns}}}Password",
            attrib={"Type": _PasswordText},
            text=credential.password,
        )

    return security


# ---------------------------------------------------------------------------
# Validation interface
# ---------------------------------------------------------------------------

class SecurityValidationError(Exception):
    """Raised by UsernameTokenValidator when authentication fails."""


class UsernameTokenValidator(ABC):
    """Abstract base class for server-side UsernameToken validation.

    Subclass and implement :meth:`get_password` to look up the expected
    password for a given username.  The base class handles digest verification
    and raises :class:`SecurityValidationError` on failure.
    """

    @abstractmethod
    def get_password(self, username: str) -> str | None:
        """Return the plain-text password for *username*, or None if unknown."""

    def validate(self, security_element: _Element) -> str:
        """Validate a ``wsse:Security`` element and return the authenticated username.

        Raises:
            SecurityValidationError: if authentication fails.
        """
        wsse_ns = NS.WSSE
        wsu_ns = NS.WSU

        token = security_element.find(f"{{{wsse_ns}}}UsernameToken")
        if token is None:
            raise SecurityValidationError("Missing wsse:UsernameToken")

        username_elem = token.find(f"{{{wsse_ns}}}Username")
        if username_elem is None or not username_elem.text:
            raise SecurityValidationError("Missing wsse:Username")
        username = username_elem.text

        password_elem = token.find(f"{{{wsse_ns}}}Password")
        if password_elem is None:
            raise SecurityValidationError("Missing wsse:Password")

        expected = self.get_password(username)
        if expected is None:
            raise SecurityValidationError(f"Unknown username: {username!r}")

        pw_type = password_elem.get("Type", _PasswordText)
        provided = password_elem.text or ""

        if pw_type == _PasswordDigest:
            nonce_elem = token.find(f"{{{wsse_ns}}}Nonce")
            created_elem = token.find(f"{{{wsu_ns}}}Created")
            if nonce_elem is None or created_elem is None:
                raise SecurityValidationError(
                    "PasswordDigest requires wsse:Nonce and wsu:Created"
                )
            try:
                nonce_bytes = base64.b64decode(nonce_elem.text or "")
            except Exception as exc:
                raise SecurityValidationError("Invalid Nonce encoding") from exc
            created = created_elem.text or ""
            expected_digest = _digest_password(nonce_bytes, created, expected)
            if not secrets.compare_digest(provided, expected_digest):
                raise SecurityValidationError("PasswordDigest mismatch")
        else:
            # PasswordText or any other type: compare plaintext
            if not secrets.compare_digest(provided, expected):
                raise SecurityValidationError("Password mismatch")

        return username


# ---------------------------------------------------------------------------
# XML-DSIG — sign and verify SOAP envelopes
# ---------------------------------------------------------------------------

class XmlSecurityError(Exception):
    """Raised when XML Signature verification or XML Encryption fails."""


def sign_envelope(
    envelope_bytes: bytes,
    private_key: Any,
    certificate: Any,
) -> bytes:
    """Sign a SOAP envelope with an XML Digital Signature (XML-DSIG).

    The ``ds:Signature`` element is inserted into the envelope using the
    enveloped-signature transform (W3C XML-DSIG §8.1).  RSA-SHA256 with
    SHA-256 digest is used by default.

    Args:
        envelope_bytes: The SOAP envelope XML as bytes.
        private_key: A ``cryptography`` RSA/EC private key object.
        certificate: A ``cryptography`` X.509 certificate object
            (or a PEM bytes string) whose public key corresponds to
            *private_key*.

    Returns:
        The signed envelope as bytes.

    Raises:
        ImportError: If ``signxml`` is not installed.
        XmlSecurityError: If signing fails.
    """
    try:
        from signxml import SignatureConstructionMethod, XMLSigner  # type: ignore[attr-defined]
    except ImportError as exc:
        raise ImportError(
            "signxml is required for XML Signature support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree

    from soapbar.core.xml import parse_xml

    try:
        root = parse_xml(envelope_bytes)
        signer = XMLSigner(method=SignatureConstructionMethod.enveloped)
        signed: Any = signer.sign(root, key=private_key, cert=[certificate])
        result_bytes: bytes = etree.tostring(signed, xml_declaration=True, encoding="utf-8")
        return result_bytes
    except Exception as exc:
        raise XmlSecurityError(f"XML Signature failed: {exc}") from exc


def verify_envelope(
    envelope_bytes: bytes,
    certificate: Any,
) -> bytes:
    """Verify the XML Digital Signature on a SOAP envelope.

    Args:
        envelope_bytes: The signed SOAP envelope as bytes.
        certificate: The expected signer's ``cryptography`` X.509 certificate
            or PEM bytes used to verify the signature.

    Returns:
        The verified envelope bytes (same content, parsed and re-serialised
        to confirm the signature covers the body).

    Raises:
        ImportError: If ``signxml`` is not installed.
        XmlSecurityError: If signature verification fails.
    """
    try:
        from signxml import XMLVerifier  # type: ignore[attr-defined]
    except ImportError as exc:
        raise ImportError(
            "signxml is required for XML Signature support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree

    from soapbar.core.xml import parse_xml

    try:
        root = parse_xml(envelope_bytes)
        verifier: Any = XMLVerifier()
        verify_result: Any = verifier.verify(root, x509_cert=certificate)
        # verify() may return a VerifyResult or list[VerifyResult]
        if isinstance(verify_result, list):
            verify_result = verify_result[0]
        signed_xml: Any = verify_result.signed_xml
        verified_bytes: bytes = etree.tostring(signed_xml, xml_declaration=True, encoding="utf-8")
        return verified_bytes
    except XmlSecurityError:
        raise
    except Exception as exc:
        raise XmlSecurityError(f"XML Signature verification failed: {exc}") from exc


# ---------------------------------------------------------------------------
# XML Encryption — encrypt and decrypt the SOAP Body
# ---------------------------------------------------------------------------

#: XML Encryption namespace URI
_XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
#: Algorithm URIs
_AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
_RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"


def encrypt_body(
    envelope_bytes: bytes,
    recipient_public_key: Any,
) -> bytes:
    """Encrypt the SOAP Body content using XML Encryption (AES-256-CBC + RSA-OAEP).

    The Body's child elements are replaced with an ``xenc:EncryptedData``
    element.  The AES-256 session key is wrapped with RSA-OAEP (SHA-256)
    using *recipient_public_key*.

    Args:
        envelope_bytes: The SOAP envelope XML as bytes.
        recipient_public_key: A ``cryptography`` RSA public key object.

    Returns:
        The envelope with an encrypted Body as bytes.

    Raises:
        ImportError: If ``cryptography`` is not installed.
        XmlSecurityError: If encryption fails.
    """
    try:
        import os

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for XML Encryption support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree

    from soapbar.core.xml import parse_xml

    try:
        root = parse_xml(envelope_bytes)
        # Find the Body element
        body = None
        for child in root:
            raw_tag = child.tag if isinstance(child.tag, str) else str(child.tag)
            local = raw_tag.split("}")[-1] if "}" in raw_tag else raw_tag
            if local == "Body":
                body = child
                break
        if body is None:
            raise XmlSecurityError("No SOAP Body element found")

        # Serialize Body children
        body_content = b"".join(etree.tostring(c) for c in body)
        if not body_content:
            return envelope_bytes  # nothing to encrypt

        # Generate AES-256 session key and IV
        session_key = os.urandom(32)
        iv = os.urandom(16)

        # Encrypt body content with AES-256-CBC
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(body_content) + padder.finalize()
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

        # Wrap session key with RSA-OAEP (SHA-256)
        wrapped_key = recipient_public_key.encrypt(
            session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Build xenc:EncryptedData element
        import base64 as _b64

        nsmap_enc: dict[str | None, str] = {"xenc": _XENC_NS}
        encrypted_data = etree.SubElement(body, f"{{{_XENC_NS}}}EncryptedData", nsmap=nsmap_enc)
        encrypted_data.set("Type", "http://www.w3.org/2001/04/xmlenc#Content")

        enc_method = etree.SubElement(encrypted_data, f"{{{_XENC_NS}}}EncryptionMethod")
        enc_method.set("Algorithm", _AES256_CBC)

        key_info = etree.SubElement(encrypted_data, f"{{{_XENC_NS}}}KeyInfo")
        enc_key = etree.SubElement(key_info, f"{{{_XENC_NS}}}EncryptedKey")
        key_method = etree.SubElement(enc_key, f"{{{_XENC_NS}}}EncryptionMethod")
        key_method.set("Algorithm", _RSA_OAEP)
        cipher_data_key = etree.SubElement(enc_key, f"{{{_XENC_NS}}}CipherData")
        cipher_value_key = etree.SubElement(cipher_data_key, f"{{{_XENC_NS}}}CipherValue")
        cipher_value_key.text = _b64.b64encode(wrapped_key).decode()

        cipher_data = etree.SubElement(encrypted_data, f"{{{_XENC_NS}}}CipherData")
        cipher_value = etree.SubElement(cipher_data, f"{{{_XENC_NS}}}CipherValue")
        # CipherValue = IV || ciphertext (base64-encoded)
        cipher_value.text = _b64.b64encode(iv + ciphertext).decode()

        # Remove original body children (now replaced by EncryptedData)
        for c in list(body):
            if c is not encrypted_data:
                body.remove(c)

        return etree.tostring(root, xml_declaration=True, encoding="utf-8")

    except XmlSecurityError:
        raise
    except Exception as exc:
        raise XmlSecurityError(f"XML Encryption failed: {exc}") from exc


def decrypt_body(
    envelope_bytes: bytes,
    private_key: Any,
) -> bytes:
    """Decrypt the SOAP Body content encrypted by :func:`encrypt_body`.

    Args:
        envelope_bytes: The SOAP envelope with an encrypted Body as bytes.
        private_key: The recipient's ``cryptography`` RSA private key.

    Returns:
        The envelope with the decrypted Body content as bytes.

    Raises:
        ImportError: If ``cryptography`` is not installed.
        XmlSecurityError: If decryption fails.
    """
    try:
        import base64 as _b64

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for XML Encryption support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree

    from soapbar.core.xml import parse_xml

    try:
        root = parse_xml(envelope_bytes)

        # Find Body
        body = None
        for child in root:
            raw_tag = child.tag if isinstance(child.tag, str) else str(child.tag)
            local = raw_tag.split("}")[-1] if "}" in raw_tag else raw_tag
            if local == "Body":
                body = child
                break
        if body is None:
            raise XmlSecurityError("No SOAP Body element found")

        # Find xenc:EncryptedData
        enc_data_tag = f"{{{_XENC_NS}}}EncryptedData"
        enc_data = body.find(enc_data_tag)
        if enc_data is None:
            return envelope_bytes  # not encrypted

        # Extract wrapped key
        wrapped_key_b64 = enc_data.findtext(
            f"{{{_XENC_NS}}}KeyInfo/{{{_XENC_NS}}}EncryptedKey"
            f"/{{{_XENC_NS}}}CipherData/{{{_XENC_NS}}}CipherValue"
        )
        if wrapped_key_b64 is None:
            raise XmlSecurityError("Missing xenc:EncryptedKey CipherValue")
        wrapped_key = _b64.b64decode(wrapped_key_b64)

        # Unwrap session key
        session_key = private_key.decrypt(
            wrapped_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Extract IV + ciphertext
        cipher_val_b64 = enc_data.findtext(
            f"{{{_XENC_NS}}}CipherData/{{{_XENC_NS}}}CipherValue"
        )
        if cipher_val_b64 is None:
            raise XmlSecurityError("Missing xenc:CipherData/CipherValue")
        iv_and_ct = _b64.b64decode(cipher_val_b64)
        iv, ciphertext = iv_and_ct[:16], iv_and_ct[16:]

        # Decrypt AES-256-CBC
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded_plain = dec.update(ciphertext) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plain_bytes = unpadder.update(padded_plain) + unpadder.finalize()

        # Replace EncryptedData with parsed children
        body.remove(enc_data)
        wrapper = etree.fromstring(b"<_w>" + plain_bytes + b"</_w>")
        for child in wrapper:
            body.append(child)

        return etree.tostring(root, xml_declaration=True, encoding="utf-8")

    except XmlSecurityError:
        raise
    except Exception as exc:
        raise XmlSecurityError(f"XML Decryption failed: {exc}") from exc


# ---------------------------------------------------------------------------
# WS-I BSP 1.1 X.509 Token Profile (S10)
# ---------------------------------------------------------------------------

def build_binary_security_token(
    certificate: Any,
    token_id: str = "X509Token-1",  # noqa: S107
) -> _Element:
    """Build a ``wsse:BinarySecurityToken`` from an X.509 certificate.

    The certificate is DER-encoded then Base64-encoded per WS-I BSP 1.1
    R3029 (``ValueType``) and R3031 (``EncodingType``).  The ``wsu:Id``
    attribute is set so that a ``wsse:SecurityTokenReference`` can reference
    this element by URI fragment.

    Args:
        certificate: A ``cryptography`` X.509 certificate object.
        token_id: Value for the ``wsu:Id`` attribute (default ``"X509Token-1"``).

    Returns:
        A ``wsse:BinarySecurityToken`` lxml element.

    Raises:
        ImportError: If ``cryptography`` is not installed.
    """
    try:
        from cryptography.hazmat.primitives.serialization import Encoding
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for X.509 token profile support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    der_bytes = certificate.public_bytes(Encoding.DER)
    b64_cert = base64.b64encode(der_bytes).decode("ascii")

    wsse_ns = NS.WSSE
    wsu_ns = NS.WSU
    nsmap: dict[str | None, str] = {"wsse": wsse_ns, "wsu": wsu_ns}

    return make_element(
        f"{{{wsse_ns}}}BinarySecurityToken",
        nsmap=nsmap,
        attrib={
            f"{{{wsu_ns}}}Id": token_id,
            "ValueType": _X509V3_VALUETYPE,
            "EncodingType": _Base64Binary,
        },
        text=b64_cert,
    )


def extract_certificate_from_security(security_element: _Element) -> Any:
    """Extract the X.509 certificate from a ``wsse:BinarySecurityToken``.

    Args:
        security_element: The ``wsse:Security`` element from the SOAP header.

    Returns:
        A ``cryptography`` X.509 certificate object.

    Raises:
        ImportError: If ``cryptography`` is not installed.
        XmlSecurityError: If no BST is found or the certificate cannot be decoded.
    """
    try:
        from cryptography import x509 as _x509
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for X.509 token profile support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    wsse_ns = NS.WSSE
    bst = security_element.find(f"{{{wsse_ns}}}BinarySecurityToken")
    if bst is None:
        raise XmlSecurityError("No wsse:BinarySecurityToken found in Security header")

    b64_text = (bst.text or "").strip()
    if not b64_text:
        raise XmlSecurityError("wsse:BinarySecurityToken is empty")

    try:
        der_bytes = base64.b64decode(b64_text)
        cert = _x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        raise XmlSecurityError(
            f"Failed to decode BinarySecurityToken certificate: {exc}"
        ) from exc

    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise XmlSecurityError("X.509 certificate is expired or not yet valid")

    return cert


def sign_envelope_bsp(
    envelope_bytes: bytes,
    private_key: Any,
    certificate: Any,
    token_id: str = "X509Token-1",  # noqa: S107
) -> bytes:
    """Sign a SOAP envelope using the WS-I BSP 1.1 X.509 token profile.

    Inserts a ``wsse:BinarySecurityToken`` (DER-encoded X.509 certificate)
    into the ``wsse:Security`` SOAP header, then applies an enveloped
    XML-DSIG signature.  The ``ds:Signature/ds:KeyInfo`` is rewritten to
    use a ``wsse:SecurityTokenReference/wsse:Reference`` that points to the
    token via ``wsu:Id``, as required by WS-I BSP 1.1.

    Args:
        envelope_bytes: The SOAP envelope XML as bytes.
        private_key: A ``cryptography`` RSA/EC private key.
        certificate: The corresponding ``cryptography`` X.509 certificate.
        token_id: The ``wsu:Id`` value assigned to the BST and referenced
            from the signature (default ``"X509Token-1"``).

    Returns:
        The signed envelope bytes with BSP-conformant key reference.

    Raises:
        ImportError: If ``signxml`` or ``cryptography`` is not installed.
        XmlSecurityError: If signing fails.
    """
    try:
        from signxml import SignatureConstructionMethod, XMLSigner  # type: ignore[attr-defined]
    except ImportError as exc:
        raise ImportError(
            "signxml is required for XML Signature support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree

    from soapbar.core.xml import parse_xml

    try:
        root = parse_xml(envelope_bytes)
        wsse_ns = NS.WSSE
        wsu_ns = NS.WSU

        # Derive envelope namespace from root tag for Header creation
        raw_root = root.tag if isinstance(root.tag, str) else str(root.tag)
        env_ns = raw_root.split("}")[0].lstrip("{") if "}" in raw_root else ""
        header_tag = f"{{{env_ns}}}Header" if env_ns else "Header"

        # Find or create soap:Header (must precede soap:Body)
        header = root.find(header_tag)
        if header is None:
            header = etree.Element(header_tag)
            root.insert(0, header)

        # Find or create wsse:Security within header
        security = header.find(f"{{{wsse_ns}}}Security")
        if security is None:
            security = etree.SubElement(
                header,
                f"{{{wsse_ns}}}Security",
                nsmap={"wsse": wsse_ns, "wsu": wsu_ns},
            )

        # Prepend wsse:BinarySecurityToken to the Security header
        bst = build_binary_security_token(certificate, token_id=token_id)
        security.insert(0, bst)

        # Sign envelope with signxml (produces ds:X509Data KeyInfo)
        signer = XMLSigner(method=SignatureConstructionMethod.enveloped)
        signed: Any = signer.sign(root, key=private_key, cert=[certificate])

        # Replace ds:X509Data in ds:KeyInfo with wsse:SecurityTokenReference
        # (BSP R3057: KeyInfo MUST contain SecurityTokenReference, not X509Data)
        for key_info in signed.findall(f".//{{{_DS_NS}}}KeyInfo"):
            x509_data = key_info.find(f"{{{_DS_NS}}}X509Data")
            if x509_data is not None:
                key_info.remove(x509_data)
                str_elem = etree.SubElement(
                    key_info,
                    f"{{{wsse_ns}}}SecurityTokenReference",
                    nsmap={"wsse": wsse_ns},
                )
                ref = etree.SubElement(str_elem, f"{{{wsse_ns}}}Reference")
                ref.set("URI", f"#{token_id}")
                ref.set("ValueType", _X509V3_VALUETYPE)

        result: bytes = etree.tostring(signed, xml_declaration=True, encoding="utf-8")
        return result

    except (XmlSecurityError, ImportError):
        raise
    except Exception as exc:
        raise XmlSecurityError(f"BSP X.509 signing failed: {exc}") from exc


def verify_envelope_bsp(envelope_bytes: bytes) -> bytes:
    """Verify a SOAP envelope signed with the WS-I BSP 1.1 X.509 token profile.

    Extracts the ``wsse:BinarySecurityToken`` certificate from the
    ``wsse:Security`` header and uses it to verify the enveloped ``ds:Signature``.

    Args:
        envelope_bytes: The signed SOAP envelope as bytes.

    Returns:
        The verified envelope bytes (same content, re-serialised after
        signature verification).

    Raises:
        ImportError: If ``signxml`` or ``cryptography`` is not installed.
        XmlSecurityError: If signature verification fails or no token is found.
    """
    try:
        from signxml import XMLVerifier  # type: ignore[attr-defined]
    except ImportError as exc:
        raise ImportError(
            "signxml is required for XML Signature support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree

    from soapbar.core.xml import parse_xml

    try:
        root = parse_xml(envelope_bytes)
        wsse_ns = NS.WSSE

        # Locate wsse:Security in any soap:Header child
        security = None
        for child in root:
            raw = child.tag if isinstance(child.tag, str) else str(child.tag)
            local = raw.split("}")[-1] if "}" in raw else raw
            if local == "Header":
                security = child.find(f"{{{wsse_ns}}}Security")
                break
        if security is None:
            raise XmlSecurityError("No wsse:Security header found")

        # Extract certificate from wsse:BinarySecurityToken
        cert = extract_certificate_from_security(security)

        # Verify using the extracted certificate (bypasses KeyInfo resolution)
        verifier: Any = XMLVerifier()
        verify_result: Any = verifier.verify(root, x509_cert=cert)
        if isinstance(verify_result, list):
            verify_result = verify_result[0]
        signed_xml: Any = verify_result.signed_xml
        verified_bytes: bytes = etree.tostring(
            signed_xml, xml_declaration=True, encoding="utf-8"
        )
        return verified_bytes

    except XmlSecurityError:
        raise
    except Exception as exc:
        raise XmlSecurityError(f"BSP X.509 verification failed: {exc}") from exc


__all__ = [
    "SecurityValidationError",
    "UsernameTokenCredential",
    "UsernameTokenValidator",
    "XmlSecurityError",
    "build_binary_security_token",
    "build_security_header",
    "decrypt_body",
    "encrypt_body",
    "extract_certificate_from_security",
    "sign_envelope",
    "sign_envelope_bsp",
    "verify_envelope",
    "verify_envelope_bsp",
]
