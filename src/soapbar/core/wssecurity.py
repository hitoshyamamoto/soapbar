# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
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
from datetime import datetime, timedelta, timezone
from typing import Any

from lxml.etree import _Element

from soapbar.core.exceptions import SoapbarError
from soapbar.core.namespaces import NS
from soapbar.core.xml import make_element, sub_element

UTC = timezone.utc

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
    timestamp_ttl: int | None = None,
) -> _Element:
    """Build a ``wsse:Security`` header element for *credential*.

    Returns a ``wsse:Security`` element ready to be added as a SOAP header.
    Per WS-Security 1.0 §6.1, the Security header MUST carry
    ``{soap_ns}mustUnderstand="1"`` so intermediaries know to process it.
    Pass *soap_ns* as the SOAP envelope namespace URI to enable this attribute.

    Args:
        credential: The UsernameToken credential to embed.
        soap_ns: SOAP envelope namespace URI; when set, adds mustUnderstand="1".
        timestamp_ttl: If given, prepend a ``wsu:Timestamp`` with ``wsu:Created``
            and ``wsu:Expires`` (set to *now* + *timestamp_ttl* seconds).
            Enables replay-window enforcement on the receiver side (N05).
    """
    wsse_ns = NS.WSSE
    wsu_ns = NS.WSU
    nsmap: dict[str | None, str] = {"wsse": wsse_ns, "wsu": wsu_ns}

    security = make_element(f"{{{wsse_ns}}}Security", nsmap=nsmap)
    if soap_ns is not None:
        security.set(f"{{{soap_ns}}}mustUnderstand", "1")

    # N05 — wsu:Timestamp: allows receiver to enforce a replay window
    if timestamp_ttl is not None:
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=timestamp_ttl)
        _fmt = "%Y-%m-%dT%H:%M:%SZ"
        ts = sub_element(
            security,
            f"{{{wsu_ns}}}Timestamp",
            attrib={f"{{{wsu_ns}}}Id": "TS-1"},
        )
        sub_element(ts, f"{{{wsu_ns}}}Created", text=now.strftime(_fmt))
        sub_element(ts, f"{{{wsu_ns}}}Expires", text=expires.strftime(_fmt))

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

class SecurityValidationError(SoapbarError):
    """Raised by UsernameTokenValidator when authentication fails."""


class UsernameTokenValidator(ABC):
    """Abstract base class for server-side UsernameToken validation.

    Subclass and implement :meth:`get_password` to look up the expected
    password for a given username.  The base class handles digest verification,
    ``wsu:Timestamp`` expiry checking (N05), and nonce replay prevention (N07).

    Subclasses that define their own ``__init__`` MUST call ``super().__init__()``
    to initialise the nonce replay cache.
    """

    #: Replay window in seconds.  Nonces seen within this window are rejected.
    #: Per WSS UsernameToken Profile 1.0 §3.2.1, five minutes is the RECOMMENDED minimum.
    nonce_ttl: int = 300

    #: Reject a ``wsu:Created`` older than this many seconds — a stale token is
    #: a replay. Defaults to ``nonce_ttl`` so that any token fresh enough to be
    #: accepted is still inside the nonce cache window: a within-window replay
    #: is caught by the nonce, an out-of-window one by this freshness check, so
    #: there is no gap. Set to ``None`` to disable freshness enforcement.
    max_created_age: int | None = 300
    #: Tolerated clock skew, in seconds, for a future-dated ``wsu:Created``.
    max_clock_skew: int | None = 300
    #: Upper bound (seconds from now) on a ``wsu:Timestamp``/``wsu:Expires`` — a
    #: far-future expiry would otherwise keep a captured token replayable for
    #: its whole span. ``None`` disables the bound.
    max_timestamp_validity: int | None = 3600

    def __init__(self) -> None:
        # N07 — nonce replay cache: maps base64-encoded nonce → expiry datetime
        self._seen_nonces: dict[str, datetime] = {}

    @staticmethod
    def _parse_ws_datetime(text: str) -> datetime:
        """Parse a WS-Security timestamp (ISO 8601, trailing ``Z``) as UTC."""
        return datetime.fromisoformat(text.strip().rstrip("Z")).replace(tzinfo=UTC)

    def _check_created_freshness(self, created_text: str, label: str) -> None:
        """Reject a ``Created`` value that is stale (replay) or implausibly
        future-dated. Governed by :attr:`max_created_age` / :attr:`max_clock_skew`."""
        if self.max_created_age is None and self.max_clock_skew is None:
            return
        try:
            created = self._parse_ws_datetime(created_text)
        except ValueError as exc:
            raise SecurityValidationError(f"Invalid {label} value: {created_text!r}") from exc
        now = datetime.now(UTC)
        if (
            self.max_clock_skew is not None
            and created > now + timedelta(seconds=self.max_clock_skew)
        ):
            raise SecurityValidationError(f"{label} is in the future (clock skew or forgery)")
        if (
            self.max_created_age is not None
            and created < now - timedelta(seconds=self.max_created_age)
        ):
            raise SecurityValidationError(f"{label} is stale — possible replay")

    def _check_and_record_nonce(self, nonce_b64: str) -> None:
        """Reject a replayed nonce; record it for *nonce_ttl* seconds (N07).

        Raises:
            SecurityValidationError: if *nonce_b64* has been seen within the
                replay window.
        """
        now = datetime.now(UTC)
        # Purge expired entries to keep the cache bounded
        self._seen_nonces = {k: v for k, v in self._seen_nonces.items() if v > now}
        if nonce_b64 in self._seen_nonces:
            raise SecurityValidationError("Nonce already used — possible replay attack")
        self._seen_nonces[nonce_b64] = now + timedelta(seconds=self.nonce_ttl)

    @abstractmethod
    def get_password(self, username: str) -> str | None:
        """Return the plain-text password for *username*, or None if unknown."""

    def validate(self, security_element: _Element) -> str:
        """Validate a ``wsse:Security`` element and return the authenticated username.

        Performs, in order:
        1. ``wsu:Timestamp`` expiry check when present (N05).
        2. ``wsse:UsernameToken`` credential verification.
        3. Nonce replay check for PasswordDigest tokens (N07).

        Raises:
            SecurityValidationError: if any check fails.
        """
        wsse_ns = NS.WSSE
        wsu_ns = NS.WSU

        # N05 — Timestamp expiry check
        ts_elem = security_element.find(f"{{{wsu_ns}}}Timestamp")
        if ts_elem is not None:
            exp_elem = ts_elem.find(f"{{{wsu_ns}}}Expires")
            if exp_elem is not None and exp_elem.text:
                try:
                    exp_text = exp_elem.text.rstrip("Z")
                    expires = datetime.fromisoformat(exp_text).replace(tzinfo=UTC)
                except ValueError as exc:
                    raise SecurityValidationError(
                        f"Invalid wsu:Expires value: {exp_elem.text!r}"
                    ) from exc
                if datetime.now(UTC) > expires:
                    raise SecurityValidationError("wsu:Timestamp has expired")
                # Bound how far Expires may reach — a far-future expiry keeps a
                # captured token replayable for its whole span.
                if (
                    self.max_timestamp_validity is not None
                    and expires
                    > datetime.now(UTC) + timedelta(seconds=self.max_timestamp_validity)
                ):
                    raise SecurityValidationError(
                        "wsu:Expires is unreasonably far in the future"
                    )
            # Freshness of the Timestamp's own Created (N05 + replay).
            ts_created = ts_elem.find(f"{{{wsu_ns}}}Created")
            if ts_created is not None and ts_created.text:
                self._check_created_freshness(ts_created.text, "wsu:Timestamp/Created")

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
            # Freshness closes the replay-after-TTL gap: a stale Created is
            # rejected even once the nonce cache has purged its entry.
            if created:
                self._check_created_freshness(created, "wsu:Created")
            # N07 — record nonce after successful auth to prevent replay
            nonce_b64_str = nonce_elem.text or ""
            self._check_and_record_nonce(nonce_b64_str)
        else:
            # PasswordText or any other type: compare plaintext
            if not secrets.compare_digest(provided, expected):
                raise SecurityValidationError("Password mismatch")
            # A PasswordText token carries no nonce, so it is inherently
            # replayable; if it does supply a Created, at least bound the window.
            # (Bare PasswordText must be used only under TLS.)
            pt_created = token.find(f"{{{wsu_ns}}}Created")
            if pt_created is not None and pt_created.text:
                self._check_created_freshness(pt_created.text, "wsu:Created")

        return username


# ---------------------------------------------------------------------------
# XML-DSIG — sign and verify SOAP envelopes
# ---------------------------------------------------------------------------

class XmlSecurityError(SoapbarError):
    """Raised when XML Signature verification or XML Encryption fails."""


def _check_unique_wsu_ids(root: _Element) -> None:
    """Reject envelopes containing duplicate ``wsu:Id`` values.

    An XML document may carry more than one attribute with the same
    ``wsu:Id`` value at parse time. Signature-wrapping attacks (WSS 1.0
    §4.3; masterprompt §18.5) exploit this by injecting a second element
    carrying the same id as a legitimate signed element; the signature
    remains valid against the original content but downstream processing
    may bind to the injected element instead. Verification paths MUST
    reject any envelope that carries duplicate ids.
    """
    wsu_id_attr = f"{{{NS.WSU}}}Id"
    seen: set[str] = set()
    for el in root.iter():
        val = el.get(wsu_id_attr)
        if val is None:
            continue
        if val in seen:
            raise XmlSecurityError(
                f"Duplicate wsu:Id {val!r} detected — signature-wrapping "
                "attempt rejected (WSS 1.0 §4.3)."
            )
        seen.add(val)


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
        from signxml.algorithms import CanonicalizationMethod

        from soapbar.core.namespaces import NS as _NS

        root = parse_xml(envelope_bytes)

        # S04 — assign wsu:Id to Body and build explicit reference list so that
        # Body and Timestamp are independently covered (BSP R5416, R5441).
        _root_tag = str(root.tag)
        _env_ns = _root_tag.split("}")[0].lstrip("{") if "}" in _root_tag else ""
        _wsu_ns = _NS.WSU
        _body_elem = root.find(f"{{{_env_ns}}}Body")
        _ref_uris: list[str] = []
        if _body_elem is not None:
            _body_id = _body_elem.get(f"{{{_wsu_ns}}}Id") or "Body-1"
            if not _body_elem.get(f"{{{_wsu_ns}}}Id"):
                _body_elem.set(f"{{{_wsu_ns}}}Id", _body_id)
            _ref_uris.append(f"#{_body_id}")
        _hdr = root.find(f"{{{_env_ns}}}Header")
        if _hdr is not None:
            _sec = _hdr.find(f"{{{_NS.WSSE}}}Security")
            if _sec is not None:
                _ts = _sec.find(f"{{{_wsu_ns}}}Timestamp")
                if _ts is not None:
                    _ts_id = _ts.get(f"{{{_wsu_ns}}}Id") or "TS-1"
                    if not _ts.get(f"{{{_wsu_ns}}}Id"):
                        _ts.set(f"{{{_wsu_ns}}}Id", _ts_id)
                    _ref_uris.append(f"#{_ts_id}")

        # S05 — use Exclusive C14N (BSP R5404); signxml defaults to C14N 1.1
        # which is rejected by WSS4J / CXF / WCF verifiers.
        signer = XMLSigner(
            method=SignatureConstructionMethod.enveloped,
            c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        signed: Any = signer.sign(
            root, key=private_key, cert=[certificate],
            reference_uri=_ref_uris if _ref_uris else None,
        )
        result_bytes: bytes = etree.tostring(signed, xml_declaration=True, encoding="utf-8")
        return result_bytes
    except Exception as exc:
        raise XmlSecurityError(f"XML Signature failed: {exc}") from exc


# Algorithm option → signxml enum maps (resolved lazily so signxml stays optional).
_SIGNATURE_METHODS = {"rsa-sha256", "rsa-sha1"}
_DIGEST_METHODS = {"sha256", "sha1"}
_C14N_METHODS = {"exclusive", "inclusive"}


def sign_element_by_id(
    doc_bytes: bytes,
    id_value: str,
    private_key: Any,
    certificate: Any,
    *,
    id_attr: str = "Id",
    signature_method: str = "rsa-sha256",
    digest_method: str = "sha256",
    c14n: str = "exclusive",
    end_cert_only: bool = True,
) -> bytes:
    """Sign one *internal* element of a document, selected by its ``Id``.

    Unlike :func:`sign_envelope` (which covers the whole SOAP envelope), this
    produces an enveloped ``ds:Signature`` with a single ``ds:Reference`` whose
    URI is ``#<id_value>`` — the standard XML-DSIG pattern for signing an inner
    element. The ``ds:Signature`` is appended to the document root, so for a
    ``<NFe><infNFe Id="NFe…">…</infNFe></NFe>`` document the signature becomes a
    sibling of ``<infNFe>``.

    The defaults (RSA-SHA256 / SHA-256 / Exclusive C14N) suit modern services.
    SEFAZ NF-e mandates the legacy set — pass ``signature_method="rsa-sha1"``,
    ``digest_method="sha1"``, ``c14n="inclusive"`` (the
    ``REC-xml-c14n-20010315`` algorithm) and keep ``end_cert_only=True`` (only
    the end-entity certificate in ``KeyInfo/X509Data``, no ``KeyValue``).

    Args:
        doc_bytes: The XML document containing the target element.
        id_value: The value of the target element's id attribute (e.g. the
            ``NFe`` + 44-char access key for NF-e).
        private_key: A ``cryptography`` private key (or PEM bytes).
        certificate: The signing X.509 certificate (object or PEM bytes).
        id_attr: Name of the attribute that holds the id. Default ``"Id"``.
        signature_method: ``"rsa-sha256"`` (default) or ``"rsa-sha1"``.
        digest_method: ``"sha256"`` (default) or ``"sha1"``.
        c14n: ``"exclusive"`` (default) or ``"inclusive"`` (C14N 1.0,
            ``http://www.w3.org/TR/2001/REC-xml-c14n-20010315``).
        end_cert_only: When True (default) ``KeyInfo`` carries only the
            end-entity certificate and no ``KeyValue``.

    Returns:
        The signed document as bytes.

    Raises:
        ImportError: If ``signxml`` is not installed.
        ValueError: If an algorithm option is unsupported.
        XmlSecurityError: If signing fails.
    """
    if signature_method not in _SIGNATURE_METHODS:
        raise ValueError(f"unsupported signature_method: {signature_method!r}")
    if digest_method not in _DIGEST_METHODS:
        raise ValueError(f"unsupported digest_method: {digest_method!r}")
    if c14n not in _C14N_METHODS:
        raise ValueError(f"unsupported c14n: {c14n!r}")

    try:
        from signxml import SignatureConstructionMethod, XMLSigner  # type: ignore[attr-defined]
    except ImportError as exc:
        raise ImportError(
            "signxml is required for XML Signature support. "
            "Install it with: pip install soapbar[security]"
        ) from exc

    from lxml import etree
    from signxml.algorithms import (
        CanonicalizationMethod,
        DigestAlgorithm,
        SignatureMethod,
    )

    from soapbar.core.xml import parse_xml

    sig_alg = (
        SignatureMethod.RSA_SHA256 if signature_method == "rsa-sha256" else SignatureMethod.RSA_SHA1
    )
    dig_alg = DigestAlgorithm.SHA256 if digest_method == "sha256" else DigestAlgorithm.SHA1
    c14n_alg = (
        CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0
        if c14n == "exclusive"
        else CanonicalizationMethod.CANONICAL_XML_1_0
    )

    # signxml refuses SHA-1 by default. SEFAZ NF-e *mandates* RSA-SHA1/SHA-1, so
    # when the caller explicitly opts in we permit it via a subclass that skips
    # the deprecation guard. SHA-256 (the default) goes through unchanged.
    class _Signer(XMLSigner):
        def check_deprecated_methods(self) -> None:
            return

    signer_cls = (
        _Signer if signature_method == "rsa-sha1" or digest_method == "sha1" else XMLSigner
    )

    try:
        root = parse_xml(doc_bytes)
        signer = signer_cls(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=sig_alg,
            digest_algorithm=dig_alg,
            c14n_algorithm=c14n_alg,
        )
        signed: Any = signer.sign(
            root,
            key=private_key,
            cert=[certificate],
            reference_uri=f"#{id_value}",
            id_attribute=id_attr,
            always_add_key_value=not end_cert_only,
        )
        _place_signature_beside_target(signed, id_attr, id_value)
        return bytes(etree.tostring(signed, xml_declaration=True, encoding="utf-8"))
    except Exception as exc:
        raise XmlSecurityError(f"Id-targeted XML Signature failed: {exc}") from exc


def _place_signature_beside_target(signed: Any, id_attr: str, id_value: str) -> None:
    """Move the ``ds:Signature`` to sit as a sibling of the element it covers.

    signxml appends the enveloped ``Signature`` to the document root. For a
    single ``<NFe>`` document that already coincides with "sibling of
    ``<infNFe>``". But inside a batch (``<enviNFe><NFe><infNFe/></NFe></enviNFe>``)
    the signature must live inside the matching ``<NFe>``, not under
    ``<enviNFe>`` — SEFAZ rejects it otherwise. The reference is to ``#<id>`` and
    the signature stays outside the signed element's subtree, so relocating it
    does not affect the digest or validity.
    """
    signature = signed.find(f"{{{_DS_NS}}}Signature")
    if signature is None:
        return
    target = next((el for el in signed.iter() if el.get(id_attr) == id_value), None)
    if target is None:
        return
    parent = target.getparent()
    # Leave it when the target is the document root (self-signed) or the
    # signature is already the target's sibling.
    if parent is None or parent is signature.getparent():
        return
    parent.append(signature)


def _signature_covers_soap_body(results: list[Any]) -> bool:
    """Return True if any verified (signed) subtree in *results* is, or
    contains, a SOAP Body — i.e. the signature actually covers the Body rather
    than only a header/Timestamp (the reference-stripping attack)."""
    soap_bodies = {f"{{{NS.SOAP_ENV}}}Body", f"{{{NS.SOAP12_ENV}}}Body"}
    for r in results:
        # signxml's VerifyResult.signed_xml is the signed lxml element (or None).
        signed = getattr(r, "signed_xml", None)
        if signed is None:
            continue
        if getattr(signed, "tag", None) in soap_bodies:
            return True
        if any(el.tag in soap_bodies for el in signed.iter()):
            return True
    return False


def verify_envelope(
    envelope_bytes: bytes,
    certificate: Any,
    expected_references: int | None = None,
    require_signed_body: bool = True,
) -> bytes:
    """Verify the XML Digital Signature on a SOAP envelope.

    Not wired into :meth:`SoapApplication.handle_request` automatically —
    callers integrating XML Signature verification MUST invoke this
    function explicitly. For production use, also pass ``expected_references``
    matching the number of ``ds:Reference`` elements the signer pinned
    (e.g. ``2`` for Body + Timestamp); this prevents an attacker from
    dropping references and still getting a successful verify.

    By default (``require_signed_body=True``) the function fails closed unless
    the signature actually covers the SOAP Body. Without this, a signature over
    only, say, the Timestamp verifies successfully and a caller could then trust
    an **unsigned** Body — the classic reference-stripping / partial-coverage
    weakness.

    Envelopes carrying duplicate ``wsu:Id`` values are rejected before
    verification as a signature-wrapping countermeasure (WSS 1.0 §4.3;
    masterprompt §18.5).

    Args:
        envelope_bytes: The signed SOAP envelope as bytes.
        certificate: The expected signer's ``cryptography`` X.509 certificate
            or PEM bytes used to verify the signature.
        expected_references: If set, the number of ``ds:Reference`` elements
            the verifier must see inside ``ds:SignedInfo``. Mismatch fails
            verification. Default ``None`` preserves pre-0.5.5 behavior.
        require_signed_body: If True (default), reject a signature that does not
            cover the SOAP Body. Set False only when a partial-coverage
            signature is deliberately expected.

    Returns:
        The verified (signed) content as bytes — the subtree the signature
        actually covers. Callers MUST act on this returned value, not on the
        original ``envelope_bytes``, so that only signed data is trusted.

    Raises:
        ImportError: If ``signxml`` is not installed.
        XmlSecurityError: If signature verification fails, the signature does
            not cover the Body (when required), or the envelope contains
            duplicate ``wsu:Id`` values.
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
        _check_unique_wsu_ids(root)
        verifier: Any = XMLVerifier()
        verify_kwargs: dict[str, Any] = {"x509_cert": certificate}
        if expected_references is not None:
            verify_kwargs["expect_references"] = expected_references
        verify_result: Any = verifier.verify(root, **verify_kwargs)
        # verify() may return a VerifyResult or list[VerifyResult]
        results = verify_result if isinstance(verify_result, list) else [verify_result]
        if require_signed_body and not _signature_covers_soap_body(results):
            raise XmlSecurityError(
                "Signature does not cover the SOAP Body (possible "
                "reference-stripping); pass require_signed_body=False only if a "
                "partial-coverage signature is intended."
            )
        signed_xml: Any = results[0].signed_xml
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
#: AES-256-GCM (XML Encryption 1.1) — authenticated encryption, used by default.
_AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
_RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
#: XML-Enc 1.1 mandates a 96-bit IV for AES-GCM; the 16-byte auth tag is
#: appended to the ciphertext (as ``cryptography``'s AESGCM already does).
_GCM_IV_LEN = 12
_GCM_TAG_LEN = 16


def encrypt_body(
    envelope_bytes: bytes,
    recipient_public_key: Any,
) -> bytes:
    """Encrypt the SOAP Body content using XML Encryption (AES-256-GCM + RSA-OAEP).

    The Body's child elements are replaced with an ``xenc:EncryptedData``
    element.  The AES-256 session key is wrapped with RSA-OAEP (SHA-256)
    using *recipient_public_key*.

    The body cipher is **AES-256-GCM** (XML-Enc 1.1), an authenticated mode:
    the 16-byte GCM tag lets the recipient detect any tampering of the
    ciphertext.  The previous AES-256-CBC output was unauthenticated, which
    exposed both ciphertext malleability and a padding oracle; GCM closes both.

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
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

        # Generate AES-256 session key and a fresh 96-bit GCM IV.
        session_key = os.urandom(32)
        iv = os.urandom(_GCM_IV_LEN)

        # Encrypt body content with AES-256-GCM (authenticated). AESGCM.encrypt
        # returns ciphertext || 16-byte tag, so no separate padding is needed.
        ciphertext = AESGCM(session_key).encrypt(iv, body_content, None)

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
        enc_method.set("Algorithm", _AES256_GCM)

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
    allow_unauthenticated_cbc: bool = False,
) -> bytes:
    """Decrypt the SOAP Body content encrypted by :func:`encrypt_body`.

    The body cipher is read from the ``xenc:EncryptionMethod`` algorithm.
    **AES-256-GCM** (the default produced by :func:`encrypt_body`) is
    authenticated: a tampered ciphertext fails the tag check and is rejected.

    Legacy **AES-256-CBC** is *unauthenticated* — it is malleable and, because
    a distinguishable unpadding error is a padding oracle, unsafe to decrypt
    for an attacker who can observe outcomes. It is therefore **refused by
    default**; pass ``allow_unauthenticated_cbc=True`` only to interoperate with
    a peer that still emits CBC and only when you accept that risk.

    Args:
        envelope_bytes: The SOAP envelope with an encrypted Body as bytes.
        private_key: The recipient's ``cryptography`` RSA private key.
        allow_unauthenticated_cbc: Permit decrypting legacy AES-256-CBC.

    Returns:
        The envelope with the decrypted Body content as bytes.

    Raises:
        ImportError: If ``cryptography`` is not installed.
        XmlSecurityError: If decryption fails, the ciphertext is tampered, or an
            unauthenticated CBC body is refused.
    """
    try:
        import base64 as _b64

        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

        # Determine the body cipher from EncryptionMethod (default: GCM).
        algorithm = _AES256_GCM
        enc_method = enc_data.find(f"{{{_XENC_NS}}}EncryptionMethod")
        if enc_method is not None:
            algorithm = enc_method.get("Algorithm", _AES256_GCM)

        # Extract IV + ciphertext
        cipher_val_b64 = enc_data.findtext(
            f"{{{_XENC_NS}}}CipherData/{{{_XENC_NS}}}CipherValue"
        )
        if cipher_val_b64 is None:
            raise XmlSecurityError("Missing xenc:CipherData/CipherValue")
        iv_and_ct = _b64.b64decode(cipher_val_b64)

        if algorithm == _AES256_GCM:
            # IV(12) || ciphertext || tag(16). AESGCM verifies the tag and
            # rejects any tampering with InvalidTag.
            iv, ct = iv_and_ct[:_GCM_IV_LEN], iv_and_ct[_GCM_IV_LEN:]
            try:
                plain_bytes = AESGCM(session_key).decrypt(iv, ct, None)
            except InvalidTag as exc:
                raise XmlSecurityError("XML Decryption failed") from exc
        elif algorithm == _AES256_CBC:
            if not allow_unauthenticated_cbc:
                raise XmlSecurityError(
                    "Refusing to decrypt unauthenticated AES-256-CBC content "
                    "(malleable / padding-oracle prone). Re-encrypt with "
                    "AES-256-GCM, or pass allow_unauthenticated_cbc=True to "
                    "accept the risk for a legacy peer."
                )
            iv, ciphertext = iv_and_ct[:16], iv_and_ct[16:]
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
            dec = cipher.decryptor()
            try:
                padded_plain = dec.update(ciphertext) + dec.finalize()
                unpadder = sym_padding.PKCS7(128).unpadder()
                plain_bytes = unpadder.update(padded_plain) + unpadder.finalize()
            except Exception as exc:
                # Uniform error: never leak whether unpadding specifically failed
                # (that distinction is the padding oracle).
                raise XmlSecurityError("XML Decryption failed") from exc
        else:
            raise XmlSecurityError(f"Unsupported encryption algorithm: {algorithm!r}")

        # Replace EncryptedData with the decrypted children, parsed through the
        # hardened parser (XXE-safe) rather than lxml's permissive default.
        from soapbar.core.xml import parse_xml as _parse_hardened
        body.remove(enc_data)
        wrapper = _parse_hardened(b"<_w>" + plain_bytes + b"</_w>")
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


def _load_x509(cert: Any) -> Any:
    """Normalize a certificate given as a ``cryptography`` X.509 object or as
    PEM/DER bytes into an X.509 object."""
    if isinstance(cert, (bytes, bytearray)):
        from cryptography import x509
        data = bytes(cert)
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError:
            return x509.load_der_x509_certificate(data)
    return cert


def _validate_bsp_cert_trust(
    cert: Any, trusted_certs: Any, ca_certs: Any
) -> None:
    """Verify that the certificate embedded in a ``BinarySecurityToken`` is
    trusted, either by pinning (``trusted_certs``) or by issuance from a
    configured CA (``ca_certs``). Fails closed when no anchor is supplied — a
    certificate carried *in the message* is not, by itself, a trust anchor.
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    if trusted_certs is None and ca_certs is None:
        raise XmlSecurityError(
            "verify_envelope_bsp: no trust anchor configured. The certificate "
            "carried in the message cannot be trusted on its own. Pass "
            "trusted_certs=[...] to pin the expected signer certificate(s), "
            "ca_certs=[...] to accept certificates issued by trusted CA(s), or "
            "verify_cert_trust=False to explicitly accept the embedded "
            "certificate (INSECURE)."
        )
    cert_der = cert.public_bytes(Encoding.DER)
    # 1. Pinning — the embedded cert must equal one of the trusted certs.
    for tc in trusted_certs or ():
        if _load_x509(tc).public_bytes(Encoding.DER) == cert_der:
            return
    # 2. Issuance — the embedded cert must be directly issued by a trusted CA
    #    (verify_directly_issued_by checks issuer name, validity, and signature).
    for ca in ca_certs or ():
        try:
            cert.verify_directly_issued_by(_load_x509(ca))
            return
        except Exception:  # noqa: S112 — try the next CA
            continue
    raise XmlSecurityError(
        "BinarySecurityToken certificate is not trusted: it matches no pinned "
        "certificate and is issued by no configured CA."
    )


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

        # S04 — assign wsu:Id to Body and build explicit reference list
        # (BSP R5416, R5441: discrete references for Body and Timestamp).
        _body_for_bsp = root.find(f"{{{env_ns}}}Body")
        _ref_uris_bsp: list[str] = []
        if _body_for_bsp is not None:
            _body_id_bsp = _body_for_bsp.get(f"{{{wsu_ns}}}Id") or "Body-1"
            if not _body_for_bsp.get(f"{{{wsu_ns}}}Id"):
                _body_for_bsp.set(f"{{{wsu_ns}}}Id", _body_id_bsp)
            _ref_uris_bsp.append(f"#{_body_id_bsp}")
        _ts_bsp = security.find(f"{{{wsu_ns}}}Timestamp")
        if _ts_bsp is not None:
            _ts_id_bsp = _ts_bsp.get(f"{{{wsu_ns}}}Id") or "TS-1"
            if not _ts_bsp.get(f"{{{wsu_ns}}}Id"):
                _ts_bsp.set(f"{{{wsu_ns}}}Id", _ts_id_bsp)
            _ref_uris_bsp.append(f"#{_ts_id_bsp}")

        # S05 — use Exclusive C14N (BSP R5404)
        from signxml.algorithms import CanonicalizationMethod
        signer = XMLSigner(
            method=SignatureConstructionMethod.enveloped,
            c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        signed: Any = signer.sign(
            root, key=private_key, cert=[certificate],
            reference_uri=_ref_uris_bsp if _ref_uris_bsp else None,
        )

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


def verify_envelope_bsp(
    envelope_bytes: bytes,
    expected_references: int | None = None,
    require_signed_body: bool = True,
    trusted_certs: Any = None,
    ca_certs: Any = None,
    verify_cert_trust: bool = True,
) -> bytes:
    """Verify a SOAP envelope signed with the WS-I BSP 1.1 X.509 token profile.

    Extracts the ``wsse:BinarySecurityToken`` certificate from the
    ``wsse:Security`` header and uses it to verify the enveloped
    ``ds:Signature``.

    **Trust anchor (GHSA-859w-52fx-hcm6).** The certificate is carried *in the
    message*, so on its own it proves only that the envelope was signed by
    *whoever supplied it* — not by a trusted party. Verifying the signature
    against that certificate without establishing trust is a signature-forgery /
    authentication bypass. This function therefore **fails closed**: you must
    anchor trust with ``trusted_certs`` (pin the expected signer certificate(s))
    and/or ``ca_certs`` (accept certificates issued by trusted CA(s)). Only pass
    ``verify_cert_trust=False`` to deliberately accept the embedded certificate
    unconditionally (INSECURE — e.g. tests).

    Not wired into :meth:`SoapApplication.handle_request` automatically —
    callers integrating BSP verification MUST invoke this function
    explicitly. For production use, also pass ``expected_references`` matching
    the number of ``ds:Reference`` elements the signer pinned (e.g. ``2``
    for Body + Timestamp); this prevents an attacker from dropping
    references and still getting a successful verify.

    Like :func:`verify_envelope`, by default (``require_signed_body=True``) it
    fails closed unless the signature covers the SOAP Body, defeating
    reference-stripping / partial-coverage signatures.

    Envelopes carrying duplicate ``wsu:Id`` values are rejected before
    verification as a signature-wrapping countermeasure (WSS 1.0 §4.3;
    masterprompt §18.5).

    Args:
        envelope_bytes: The signed SOAP envelope as bytes.
        expected_references: If set, the number of ``ds:Reference``
            elements the verifier must see inside ``ds:SignedInfo``.
            Mismatch fails verification. Default ``None`` preserves
            pre-0.5.5 behavior.
        require_signed_body: If True (default), reject a signature that does not
            cover the SOAP Body. Set False only when a partial-coverage
            signature is deliberately expected.
        trusted_certs: Iterable of pinned signer certificates (``cryptography``
            X.509 objects or PEM/DER bytes); the embedded certificate must equal
            one of them.
        ca_certs: Iterable of trusted issuer CA certificates; the embedded
            certificate must be directly issued by one of them.
        verify_cert_trust: If True (default), enforce the trust anchor above.
            Set False to accept the embedded certificate unconditionally
            (INSECURE).

    Returns:
        The verified (signed) content as bytes — the subtree the signature
        actually covers. Callers MUST act on this returned value, not on the
        original ``envelope_bytes``.

    Raises:
        ImportError: If ``signxml`` or ``cryptography`` is not installed.
        XmlSecurityError: If signature verification fails, the signature does
            not cover the Body (when required), no token is found, or the
            envelope contains duplicate ``wsu:Id`` values.
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
        _check_unique_wsu_ids(root)
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

        # Anchor trust BEFORE relying on the certificate — the token is
        # attacker-controlled, so a valid signature over it means nothing until
        # the certificate itself is trusted (GHSA-859w-52fx-hcm6).
        if verify_cert_trust:
            _validate_bsp_cert_trust(cert, trusted_certs, ca_certs)

        # Verify using the extracted certificate (bypasses KeyInfo resolution)
        verifier: Any = XMLVerifier()
        verify_kwargs: dict[str, Any] = {"x509_cert": cert}
        if expected_references is not None:
            verify_kwargs["expect_references"] = expected_references
        verify_result: Any = verifier.verify(root, **verify_kwargs)
        results = verify_result if isinstance(verify_result, list) else [verify_result]
        if require_signed_body and not _signature_covers_soap_body(results):
            raise XmlSecurityError(
                "Signature does not cover the SOAP Body (possible "
                "reference-stripping); pass require_signed_body=False only if a "
                "partial-coverage signature is intended."
            )
        signed_xml: Any = results[0].signed_xml
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
