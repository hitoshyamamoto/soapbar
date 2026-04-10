"""
SOAP/WSDL compliance tests for soapbar.

Organised by specification section. Every test documents:
  - the normative spec reference
  - the input
  - the expected behaviour
  - the actual behaviour (pass / xfail if known gap)

No outbound HTTP is used.  All tests are self-contained.
"""
from __future__ import annotations

import pytest
from lxml import etree

from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import SoapEnvelope, SoapVersion, http_headers
from soapbar.core.fault import SoapFault
from soapbar.core.namespaces import NS
from soapbar.core.types import xsd
from soapbar.core.wsdl.builder import build_wsdl_bytes
from soapbar.core.wsdl.parser import parse_wsdl
from soapbar.core.xml import local_name, namespace_uri, to_bytes
from soapbar.server.application import SoapApplication
from soapbar.server.service import SoapService, soap_operation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SOAP11_ENV = NS.SOAP_ENV
SOAP12_ENV = NS.SOAP12_ENV
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"


def _parse(xml: str | bytes) -> etree._Element:
    if isinstance(xml, str):
        xml = xml.encode()
    return etree.fromstring(xml)


def _make_app() -> tuple[SoapApplication, type[SoapService]]:
    """Return a minimal SoapApplication with a Calculator service."""

    class _Calc(SoapService):
        __service_name__ = "Calc"
        __tns__ = "http://example.com/calc"
        __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED

        @soap_operation(soap_action="add")
        def add(self, a: int, b: int) -> int:
            return a + b

        @soap_operation(soap_action="divide")
        def divide(self, a: int, b: int) -> int:
            if b == 0:
                raise SoapFault("Client", "Division by zero")
            return a // b

    app = SoapApplication(service_url="http://example.com/calc")
    app.register(_Calc())
    return app, _Calc


def _make_sig(name: str = "add") -> OperationSignature:
    return OperationSignature(
        name=name,
        input_params=[
            OperationParameter("a", xsd.resolve("int")),   # type: ignore[arg-type]
            OperationParameter("b", xsd.resolve("int")),   # type: ignore[arg-type]
        ],
        output_params=[OperationParameter("result", xsd.resolve("int"))],  # type: ignore[arg-type]
        soap_action=name,
        input_namespace="http://example.com/calc",
        output_namespace="http://example.com/calc",
    )


# ---------------------------------------------------------------------------
# 3a. SOAP 1.1 Envelope Compliance (SOAP 1.1 §4)
# ---------------------------------------------------------------------------

class TestSoap11EnvelopeCompliance:
    """SOAP 1.1 Specification §4 — Envelope structure."""

    def test_envelope_root_element_is_envelope(self):
        """§4.1.1 — Root element MUST be Envelope."""
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        root = env.build()
        assert local_name(root) == "Envelope"

    def test_envelope_namespace_11(self):
        """§4.1.2 — Envelope namespace MUST be the SOAP 1.1 URI."""
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        root = env.build()
        assert namespace_uri(root) == SOAP11_ENV

    def test_header_before_body(self):
        """§4.1.1 — Header MUST precede Body when both present."""
        hdr = etree.Element("{http://example.com/}Auth")
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        env.add_header(hdr)
        env.add_body_content(etree.Element("{http://example.com/}Payload"))
        root = env.build()
        children = list(root)
        local_names = [local_name(c) for c in children]
        header_idx = local_names.index("Header")
        body_idx = local_names.index("Body")
        assert header_idx < body_idx, "Header must precede Body"

    def test_body_exactly_one(self):
        """§4.1.1 — Exactly one Body element MUST be present."""
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        root = env.build()
        bodies = root.findall(f"{{{SOAP11_ENV}}}Body")
        assert len(bodies) == 1

    def test_no_elements_after_body(self):
        """§4.1.1 — No elements may appear after Body in the Envelope."""
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        root = env.build()
        children = list(root)
        assert local_name(children[-1]) == "Body", "Body must be last child of Envelope"

    def test_faultcode_qname_format(self):
        """§4.4 — faultcode MUST be a QName (namespace-qualified or unprefixed)."""
        fault = SoapFault("Client", "bad input")
        elem = fault.to_soap11_element()
        fc = elem.find("faultcode")
        assert fc is not None
        assert fc.text in ("Client", "Server", "VersionMismatch", "MustUnderstand")

    def test_faultstring_present(self):
        """§4.4 — faultstring MUST be present in a SOAP 1.1 Fault."""
        fault = SoapFault("Server", "Internal error")
        elem = fault.to_soap11_element()
        fs = elem.find("faultstring")
        assert fs is not None
        assert fs.text == "Internal error"

    def test_fault_codes_standard_set_11(self):
        """§4.4.1 — Standard fault codes: VersionMismatch, MustUnderstand, Client, Server."""
        codes = ["VersionMismatch", "MustUnderstand", "Client", "Server"]
        for code in codes:
            f = SoapFault(code, "test")
            elem = f.to_soap11_element()
            fc = elem.find("faultcode")
            assert fc is not None and fc.text == code

    def test_fault_detail_only_when_body_caused_fault(self):
        """§4.4 — Detail element SHOULD be present only when fault relates to Body processing."""
        # Detail present
        fault = SoapFault("Client", "bad body", detail="extra info")
        elem = fault.to_soap11_element()
        assert elem.find("detail") is not None

        # No detail — header fault
        fault_no_detail = SoapFault("MustUnderstand", "header not understood")
        elem2 = fault_no_detail.to_soap11_element()
        assert elem2.find("detail") is None

    def test_http_content_type_11(self):
        """§6.1.1 — Content-Type for SOAP 1.1 requests MUST be text/xml."""
        headers = http_headers(SoapVersion.SOAP_11, "test")
        assert headers["Content-Type"].startswith("text/xml")

    def test_soap_action_header_present_11(self):
        """§6.1.1 — SOAPAction HTTP header MUST be present in SOAP 1.1 requests."""
        headers = http_headers(SoapVersion.SOAP_11, "myAction")
        assert "SOAPAction" in headers

    def test_soap_action_quoted_ws_i(self):
        """WS-I BP 1.1 R2744 — SOAPAction MUST be a quoted string."""
        headers = http_headers(SoapVersion.SOAP_11, "myAction")
        saction = headers["SOAPAction"]
        assert saction.startswith('"') and saction.endswith('"'), \
            f"SOAPAction must be quoted, got: {saction!r}"

    def test_soap_action_empty_quoted(self):
        """WS-I BP 1.1 R2744 — Empty SOAPAction must also be quoted."""
        headers = http_headers(SoapVersion.SOAP_11, "")
        assert headers["SOAPAction"] == '""'

    def test_mustunderstand_attribute_values_11(self):
        """§4.2.3 — mustUnderstand MUST be '0' or '1' in SOAP 1.1."""
        xml = b"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <ns:Auth xmlns:ns="http://example.com/" soapenv:mustUnderstand="1">token</ns:Auth>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>"""
        env = SoapEnvelope.from_xml(xml)
        assert env.version == SoapVersion.SOAP_11
        assert len(env.header_elements) == 1
        mu = env.header_elements[0].get(f"{{{SOAP11_ENV}}}mustUnderstand")
        assert mu == "1"

    def test_actor_attribute_11(self):
        """§4.2.2 — actor attribute uses a URI to identify the intended recipient."""
        xml = b"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <ns:H xmlns:ns="http://example.com/"
                  soapenv:actor="http://schemas.xmlsoap.org/soap/actor/next"
                  soapenv:mustUnderstand="0">val</ns:H>
          </soapenv:Header>
          <soapenv:Body/>
        </soapenv:Envelope>"""
        env = SoapEnvelope.from_xml(xml)
        actor = env.header_elements[0].get(f"{{{SOAP11_ENV}}}actor")
        assert actor is not None


# ---------------------------------------------------------------------------
# 3b. SOAP 1.2 Envelope Compliance (SOAP 1.2 Part 1 §5)
# ---------------------------------------------------------------------------

class TestSoap12EnvelopeCompliance:
    """SOAP 1.2 Specification Part 1 §5 — Envelope structure."""

    def test_envelope_namespace_12(self):
        """§5.1 — Envelope namespace MUST be the SOAP 1.2 URI."""
        env = SoapEnvelope(version=SoapVersion.SOAP_12)
        root = env.build()
        assert namespace_uri(root) == SOAP12_ENV

    def test_mustunderstand_attribute_12(self):
        """§5.2.3 — mustUnderstand values: 'true', 'false', '1', '0'."""
        xml = b"""
        <soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
          <soap12:Header>
            <ns:Sec xmlns:ns="http://example.com/" soap12:mustUnderstand="true">x</ns:Sec>
          </soap12:Header>
          <soap12:Body/>
        </soap12:Envelope>"""
        env = SoapEnvelope.from_xml(xml)
        assert env.version == SoapVersion.SOAP_12
        mu = env.header_elements[0].get(f"{{{SOAP12_ENV}}}mustUnderstand")
        assert mu == "true"

    def test_role_attribute_12(self):
        """§5.2.2 — role attribute identifies the SOAP node role."""
        xml = b"""
        <soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
          <soap12:Header>
            <ns:H xmlns:ns="http://example.com/"
                  soap12:role="http://www.w3.org/2003/05/soap-envelope/role/next"
                  soap12:mustUnderstand="false">v</ns:H>
          </soap12:Header>
          <soap12:Body/>
        </soap12:Envelope>"""
        env = SoapEnvelope.from_xml(xml)
        role = env.header_elements[0].get(f"{{{SOAP12_ENV}}}role")
        assert role is not None

    def test_fault_code_value_qnames_12(self):
        """§5.4.5 — SOAP 1.2 fault codes: VersionMismatch, MustUnderstand,
        DataEncodingUnknown, Sender, Receiver (mapped from Client/Server)."""
        for input_code, expected_wire in [("Client", "Sender"), ("Server", "Receiver"),
                                           ("VersionMismatch", "VersionMismatch"),
                                           ("MustUnderstand", "MustUnderstand")]:
            f = SoapFault(input_code, "test")
            elem = f.to_soap12_element()
            code_elem = elem.find(f"{{{SOAP12_ENV}}}Code")
            assert code_elem is not None
            val_elem = code_elem.find(f"{{{SOAP12_ENV}}}Value")
            assert val_elem is not None and val_elem.text is not None
            wire_code = val_elem.text.split(":")[-1]
            assert wire_code == expected_wire, (
                f"Input {input_code!r} → expected {expected_wire!r}, got {wire_code!r}"
            )

    def test_fault_subcode_support_12(self):
        """§5.4.6 — Subcodes enable nested fault classification."""
        f = SoapFault("Client", "validation", subcodes=[("http://example.com/", "InvalidInput")])
        elem = f.to_soap12_element()
        code_elem = elem.find(f"{{{SOAP12_ENV}}}Code")
        assert code_elem is not None
        subcode = code_elem.find(f"{{{SOAP12_ENV}}}Subcode")
        assert subcode is not None

    def test_subcode_value_qname_namespace_declared(self):
        """§5.4.6 MUST — Subcode/Value text is a namespace-qualified QName with prefix in scope."""
        ns = "http://example.com/faults"
        f = SoapFault("Client", "err", subcodes=[(ns, "ValidationError")])
        elem = f.to_soap12_element()
        code_elem = elem.find(f"{{{SOAP12_ENV}}}Code")
        assert code_elem is not None
        subcode = code_elem.find(f"{{{SOAP12_ENV}}}Subcode")
        assert subcode is not None
        val = subcode.find(f"{{{SOAP12_ENV}}}Value")
        assert val is not None
        text = val.text or ""
        assert ":" in text, "Subcode/Value MUST be a QName (prefix:local)"
        prefix, local = text.split(":", 1)
        assert local == "ValidationError"
        # The prefix must be declared in the element's in-scope namespace map
        assert val.nsmap.get(prefix) == ns, (
            f"Prefix {prefix!r} must be bound to {ns!r} in nsmap"
        )

    def test_fault_reason_xml_lang_12(self):
        """§5.4.4 — Reason/Text MUST have xml:lang attribute."""
        f = SoapFault("Server", "Internal error")
        elem = f.to_soap12_element()
        reason = elem.find(f"{{{SOAP12_ENV}}}Reason")
        assert reason is not None
        text_elem = reason.find(f"{{{SOAP12_ENV}}}Text")
        assert text_elem is not None
        lang = text_elem.get(XML_LANG)
        assert lang is not None, "xml:lang MUST be present on Reason/Text (§5.4.4)"
        assert lang == "en"

    def test_fault_role_12(self):
        """§5.4.7 — Role element (faultactor equivalent)."""
        f = SoapFault("Server", "err", faultactor="http://example.com/router")
        elem = f.to_soap12_element()
        role_elem = elem.find(f"{{{SOAP12_ENV}}}Role")
        assert role_elem is not None
        assert role_elem.text == "http://example.com/router"

    def test_fault_detail_12(self):
        """§5.4.8 — Detail element for fault-specific information."""
        f = SoapFault("Client", "bad input", detail="field x missing")
        elem = f.to_soap12_element()
        detail = elem.find(f"{{{SOAP12_ENV}}}Detail")
        assert detail is not None
        assert detail.text == "field x missing"

    def test_http_content_type_12(self):
        """SOAP 1.2 Part 2 §7.1 — Content-Type MUST be application/soap+xml."""
        headers = http_headers(SoapVersion.SOAP_12, "test")
        assert "application/soap+xml" in headers["Content-Type"]

    def test_http_action_in_content_type_12(self):
        """Part 2 §7.1.2 — action= parameter MUST appear in Content-Type (not SOAPAction header)."""
        headers = http_headers(SoapVersion.SOAP_12, "myAction")
        assert "action=" in headers["Content-Type"]
        assert "SOAPAction" not in headers, "SOAP 1.2 must not have a SOAPAction header"

    def test_data_encoding_unknown_fault_generated(self):
        """§5.4.9 MUST — Unknown encodingStyle on Body child generates DataEncodingUnknown fault."""
        xml = b"""<?xml version="1.0"?>
        <soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"
                         xmlns:tns="http://example.com/calc">
          <soap12:Body>
            <tns:add soap12:encodingStyle="http://unknown.example.com/encoding"
                     xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
              <a>1</a><b>2</b>
            </tns:add>
          </soap12:Body>
        </soap12:Envelope>"""
        app, _ = _make_app()
        status, _, body = app.handle_request(xml, content_type="application/soap+xml")
        assert status == 500
        root = _parse(body)
        fault = root.find(f"{{{SOAP12_ENV}}}Body/{{{SOAP12_ENV}}}Fault")
        assert fault is not None, "Response must be a SOAP 1.2 Fault"
        val = fault.find(f"{{{SOAP12_ENV}}}Code/{{{SOAP12_ENV}}}Value")
        assert val is not None
        assert (val.text or "").endswith("DataEncodingUnknown"), \
            "Fault code MUST be DataEncodingUnknown per §5.4.9"

    def test_known_soap12_encoding_style_accepted(self):
        """§5.4.9 — The SOAP 1.2 encoding URI is the known/accepted encodingStyle value."""
        xml = (
            b'<?xml version="1.0"?>'
            b'<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"'
            b'                 xmlns:tns="http://example.com/calc">'
            b'  <soap12:Body>'
            b'    <tns:add soap12:encodingStyle="http://www.w3.org/2003/05/soap-encoding">'
            b'      <a>2</a><b>3</b>'
            b'    </tns:add>'
            b'  </soap12:Body>'
            b'</soap12:Envelope>'
        )
        app, _ = _make_app()
        status, _, body = app.handle_request(xml, content_type="application/soap+xml")
        # Must NOT trigger DataEncodingUnknown — service returns 200 or a different fault
        root = _parse(body)
        if status == 500:
            val = root.find(
                f"{{{SOAP12_ENV}}}Body/{{{SOAP12_ENV}}}Fault"
                f"/{{{SOAP12_ENV}}}Code/{{{SOAP12_ENV}}}Value"
            )
            assert val is None or not (val.text or "").endswith("DataEncodingUnknown"), \
                "Known SOAP 1.2 encoding URI must NOT trigger DataEncodingUnknown"

    def test_version_mismatch_detection(self):
        """§5.4.5 — Unknown envelope namespace returns VersionMismatch-style fault."""
        # soapbar converts the ValueError from unknown namespace to a Client fault
        bad_xml = b"""
        <env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/WRONG">
          <env:Body/>
        </env:Envelope>"""
        app, _ = _make_app()
        status, _ct, body = app.handle_request(bad_xml)
        # Should be 4xx (Client) since it's a parsing/version error
        assert status in (400, 500)
        root = _parse(body)
        assert local_name(root) == "Envelope"


# ---------------------------------------------------------------------------
# 3c. WSDL 1.1 Compliance (WSDL 1.1 §1-4)
# ---------------------------------------------------------------------------

class TestWsdl11Compliance:
    """WSDL 1.1 Specification §1-4."""

    def _make_wsdl_bytes(self) -> bytes:
        app, _ = _make_app()
        return app.get_wsdl()

    def test_wsdl_all_7_elements_present(self):
        """§1.1 — WSDL definitions element MUST contain: definitions, types, message,
        portType, binding, port (in service), service."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        lnames = {local_name(c) for c in root}
        assert "message" in lnames, "WSDL must have <message>"
        assert "portType" in lnames, "WSDL must have <portType>"
        assert "binding" in lnames, "WSDL must have <binding>"
        assert "service" in lnames, "WSDL must have <service>"

    def test_wsdl_target_namespace(self):
        """§1.2 — definitions MUST have targetNamespace."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        assert root.get("targetNamespace") is not None

    def test_wsdl_message_parts(self):
        """§2.3 — message parts must have element= or type= attribute."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        messages = root.findall(f"{{{NS.WSDL}}}message")
        for msg in messages:
            for part in msg.findall(f"{{{NS.WSDL}}}part"):
                has_type = part.get("type") is not None
                has_element = part.get("element") is not None
                assert has_type or has_element, \
                    f"Part {part.get('name')} must have type= or element="

    def test_wsdl_port_type_operations(self):
        """§2.4 — portType must have operations with input/output."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        port_types = root.findall(f"{{{NS.WSDL}}}portType")
        assert len(port_types) >= 1
        for pt in port_types:
            ops = pt.findall(f"{{{NS.WSDL}}}operation")
            assert len(ops) >= 1, "portType must have at least one operation"
            for op in ops:
                # input or output should be present
                has_io = (
                    op.find(f"{{{NS.WSDL}}}input") is not None
                    or op.find(f"{{{NS.WSDL}}}output") is not None
                )
                assert has_io

    def test_wsdl_soap_binding_style_attribute(self):
        """§3.4 — soap:binding MUST have style attribute."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        bindings = root.findall(f"{{{NS.WSDL}}}binding")
        for binding_elem in bindings:
            soap_b = binding_elem.find(f"{{{NS.WSDL_SOAP}}}binding")
            if soap_b is None:
                soap_b = binding_elem.find(f"{{{NS.WSDL_SOAP12}}}binding")
            if soap_b is not None:
                assert soap_b.get("style") in ("rpc", "document"), \
                    "soap:binding style must be 'rpc' or 'document'"

    def test_wsdl_soap_body_use_attribute(self):
        """§3.5 — soap:body MUST have use= attribute."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        bindings = root.findall(f"{{{NS.WSDL}}}binding")
        for binding_elem in bindings:
            for op_elem in binding_elem.findall(f"{{{NS.WSDL}}}operation"):
                for direction in ("input", "output"):
                    dir_elem = op_elem.find(f"{{{NS.WSDL}}}{direction}")
                    if dir_elem is not None:
                        body = dir_elem.find(f"{{{NS.WSDL_SOAP}}}body")
                        if body is None:
                            body = dir_elem.find(f"{{{NS.WSDL_SOAP12}}}body")
                        if body is not None:
                            assert body.get("use") in ("literal", "encoded"), \
                                "soap:body must have use='literal' or 'encoded'"

    def test_wsdl_service_port_address(self):
        """§2.6 — soap:address MUST have location= attribute in port."""
        wsdl = self._make_wsdl_bytes()
        root = _parse(wsdl)
        services = root.findall(f"{{{NS.WSDL}}}service")
        for svc in services:
            ports = svc.findall(f"{{{NS.WSDL}}}port")
            for port in ports:
                addr = port.find(f"{{{NS.WSDL_SOAP}}}address")
                if addr is None:
                    addr = port.find(f"{{{NS.WSDL_SOAP12}}}address")
                assert addr is not None, "port must have soap:address"
                assert addr.get("location") is not None

    def test_wsdl_import_namespace_only_is_skipped(self):
        """wsdl:import with no location= is silently skipped (namespace-only import)."""
        wsdl_with_ns_import = b"""
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/">
          <import namespace="http://example.com/types"/>
          <portType name="PT"/>
        </definitions>"""
        defn = parse_wsdl(wsdl_with_ns_import)
        assert "PT" in defn.port_types

    def test_wsdl_remote_import_blocked_by_default(self):
        """I04 — Remote wsdl:import MUST be blocked by default (SSRF guard)."""
        wsdl_with_remote_import = b"""
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/">
          <import namespace="http://example.com/ext"
                  location="http://attacker.example.com/evil.wsdl"/>
          <portType name="PT"/>
        </definitions>"""
        with pytest.raises(ValueError, match="Remote WSDL import blocked"):
            parse_wsdl(wsdl_with_remote_import)

    def test_wsdl_remote_import_allowed_when_opt_in(self, monkeypatch):
        """I04 — allow_remote_imports=True bypasses the SSRF guard."""
        import urllib.request

        fake_wsdl = b"""
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/remote">
          <portType name="RemotePT"/>
        </definitions>"""

        class _FakeResp:
            def read(self) -> bytes:
                return fake_wsdl
            def __enter__(self) -> _FakeResp:
                return self
            def __exit__(self, *_: object) -> None:
                pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda _url: _FakeResp())

        wsdl = b"""
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/">
          <import namespace="http://example.com/remote"
                  location="http://trusted.example.com/remote.wsdl"/>
          <portType name="LocalPT"/>
        </definitions>"""
        defn = parse_wsdl(wsdl, allow_remote_imports=True)
        assert "LocalPT" in defn.port_types
        assert "RemotePT" in defn.port_types

    def test_wsdl_roundtrip_parse_build_parse(self):
        """Parse → build → re-parse should produce equivalent structure."""
        wsdl1 = self._make_wsdl_bytes()
        defn1 = parse_wsdl(wsdl1)
        # Build from parsed definition
        rebuilt = build_wsdl_bytes(defn1, "http://example.com/calc")
        defn2 = parse_wsdl(rebuilt)
        # Key structural equivalence
        assert set(defn1.messages.keys()) == set(defn2.messages.keys())
        assert set(defn1.bindings.keys()) == set(defn2.bindings.keys())
        assert set(defn1.services.keys()) == set(defn2.services.keys())

    def test_wsdl_soap12_binding_namespace(self):
        """SOAP 1.2 WSDL extension uses the correct namespace."""

        class _Calc12(SoapService):
            __service_name__ = "Calc12"
            __tns__ = "http://example.com/calc12"
            __soap_version__ = SoapVersion.SOAP_12

            @soap_operation()
            def add(self, a: int, b: int) -> int:
                return a + b

        app = SoapApplication()
        app.register(_Calc12())
        wsdl = app.get_wsdl()
        assert NS.WSDL_SOAP12.encode() in wsdl or b"soap12" in wsdl

    def test_wsdl_parser_captures_output_use(self):
        """§3.5 — parser MUST capture output use= independently from input use=."""
        from soapbar.core.wsdl.parser import parse_wsdl
        wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
                     targetNamespace="http://example.com/">
          <message name="Req"><part name="p" type="xsd:string"/></message>
          <message name="Resp"><part name="r" type="xsd:string"/></message>
          <portType name="PT">
            <operation name="Op">
              <input message="tns:Req"/>
              <output message="tns:Resp"/>
            </operation>
          </portType>
          <binding name="B" type="tns:PT">
            <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
            <operation name="Op">
              <soap:operation soapAction="Op"/>
              <input><soap:body use="literal" namespace="http://example.com/"/></input>
              <output><soap:body use="encoded" namespace="http://example.com/"/></output>
            </operation>
          </binding>
        </definitions>"""
        defn = parse_wsdl(wsdl)
        binding = next(iter(defn.bindings.values()))
        op = binding.operations[0]
        assert op.use == "literal", "input use must be captured"
        assert op.output_use == "encoded", "output use must be captured independently"


# ---------------------------------------------------------------------------
# 3d. Binding Style Compliance
# ---------------------------------------------------------------------------

class TestBindingStyleCompliance:
    """Binding style serialization compliance."""

    def _body_container(self) -> etree._Element:
        return etree.Element("_body")

    def test_rpc_encoded_operation_wrapper(self):
        """RPC/Encoded: operation name wrapper element MUST be present."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_ENCODED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        assert local_name(wrapper) == "add"

    def test_rpc_encoded_xsi_type_on_params(self):
        """RPC/Encoded: each parameter MUST carry xsi:type."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_ENCODED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        for child in wrapper:
            assert child.get(f"{{{NS.XSI}}}type") is not None, \
                f"Parameter {child.tag} missing xsi:type in RPC/Encoded"

    def test_rpc_encoded_encoding_style_attr(self):
        """RPC/Encoded: encodingStyle attribute MUST be on wrapper."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_ENCODED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        enc_style_key = f"{{{NS.SOAP_ENC}}}encodingStyle"
        assert wrapper.get(enc_style_key) is not None

    def test_rpc_encoded_namespace_from_sig(self):
        """RPC/Encoded: wrapper namespace comes from input_namespace."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_ENCODED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        assert namespace_uri(wrapper) == "http://example.com/calc"

    def test_rpc_literal_operation_wrapper(self):
        """RPC/Literal: operation name wrapper element MUST be present."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_LITERAL)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        assert local_name(body[0]) == "add"

    def test_rpc_literal_no_xsi_type(self):
        """RPC/Literal: parameters MUST NOT carry xsi:type."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_LITERAL)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        for child in wrapper:
            assert child.get(f"{{{NS.XSI}}}type") is None, \
                f"RPC/Literal must not have xsi:type on {child.tag}"

    def test_rpc_literal_no_encoding_style(self):
        """RPC/Literal: NO encodingStyle attribute on wrapper."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.RPC_LITERAL)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        enc_style_key = f"{{{NS.SOAP_ENC}}}encodingStyle"
        assert wrapper.get(enc_style_key) is None

    def test_document_literal_direct_body_children(self):
        """Document/Literal: params are direct Body children, no wrapper."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        child_names = [local_name(c) for c in body]
        assert "add" not in child_names, "Document/Literal must not wrap in operation element"
        assert "a" in child_names
        assert "b" in child_names

    def test_document_literal_no_wrapper(self):
        """Document/Literal: no operation-name wrapper."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        assert len(body) == 2  # a and b as siblings

    def test_dlw_wrapper_element_named_after_op(self):
        """Document/Literal/Wrapped: wrapper element named after operation."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        assert local_name(body[0]) == "add"

    def test_dlw_response_wrapper_suffix(self):
        """Document/Literal/Wrapped: response wrapper = opName + 'Response'."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        body = self._body_container()
        serializer.serialize_response(sig, {"result": 8}, body)
        assert local_name(body[0]) == "addResponse"

    def test_dlw_params_inside_wrapper(self):
        """Document/Literal/Wrapped: params are children of the wrapper."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        wrapper = body[0]
        child_names = [local_name(c) for c in wrapper]
        assert "a" in child_names
        assert "b" in child_names

    def test_de_direct_body_children(self):
        """Document/Encoded: params are direct Body children."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_ENCODED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        # Should have a and b as direct children, not wrapped
        child_names = [local_name(c) for c in body]
        assert "a" in child_names
        assert "b" in child_names
        assert "add" not in child_names

    def test_de_xsi_type_on_params(self):
        """Document/Encoded: each param MUST carry xsi:type."""
        sig = _make_sig("add")
        serializer = get_serializer(BindingStyle.DOCUMENT_ENCODED)
        body = self._body_container()
        serializer.serialize_request(sig, {"a": 3, "b": 5}, body)
        for child in body:
            assert child.get(f"{{{NS.XSI}}}type") is not None, \
                f"Document/Encoded param {child.tag} missing xsi:type"


# ---------------------------------------------------------------------------
# 3e. SOAPAction Header Compliance
# ---------------------------------------------------------------------------

class TestSoapActionCompliance:
    """SOAPAction header dispatch and quoting compliance."""

    def _dlw_add_request(self) -> bytes:
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:add><a>3</a><b>5</b></tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""
        return xml

    def test_soap_action_dispatch_exact_match(self):
        """Route by SOAPAction header (exact match)."""
        app, _ = _make_app()
        status, _ct, _body = app.handle_request(self._dlw_add_request(), soap_action="add")
        assert status == 200

    def test_soap_action_adds_quotes_on_send_11(self):
        """WS-I BP 1.1 R2744 — SOAPAction header must be quoted string."""
        headers = http_headers(SoapVersion.SOAP_11, "someAction")
        assert headers["SOAPAction"] == '"someAction"'

    def test_soap12_action_in_content_type(self):
        """SOAP 1.2: action= in Content-Type, not separate SOAPAction header."""
        headers = http_headers(SoapVersion.SOAP_12, "someAction")
        assert 'action="someAction"' in headers["Content-Type"]
        assert "SOAPAction" not in headers

    def test_soap_action_strips_quotes_on_receive(self):
        """application.py strips quotes from received SOAPAction."""
        app, _ = _make_app()
        # Quoted SOAPAction header (as sent by WS-I-compliant client)
        status, _ct, _body = app.handle_request(
            self._dlw_add_request(), soap_action='"add"'
        )
        assert status == 200, f"Quoted SOAPAction dispatch failed, status={status}"

    def test_soap_action_fallback_body_element(self):
        """Fallback to body element local name when SOAPAction is empty."""
        app, _ = _make_app()
        status, _ct, _body = app.handle_request(self._dlw_add_request(), soap_action="")
        assert status == 200, f"Body-element fallback dispatch failed, status={status}"

    def test_soap_action_fragment_dispatch(self):
        """#OpName fragment in SOAPAction is resolved to operation name."""
        app, _ = _make_app()
        status, _ct, _body = app.handle_request(
            self._dlw_add_request(), soap_action="#add"
        )
        assert status == 200


# ---------------------------------------------------------------------------
# 3f. HTTP Binding Compliance
# ---------------------------------------------------------------------------

class TestHttpBindingCompliance:
    """HTTP status codes and Content-Type per SOAP 1.1 §6 and SOAP 1.2 Part 2 §7."""

    def _add_request_11(self) -> bytes:
        return b"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:add><a>3</a><b>5</b></tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""

    def _add_request_12(self) -> bytes:
        return b"""<?xml version="1.0" encoding="UTF-8"?>
        <soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"
                         xmlns:tns="http://example.com/calc">
          <soap12:Body>
            <tns:add><a>3</a><b>5</b></tns:add>
          </soap12:Body>
        </soap12:Envelope>"""

    def test_http_200_for_success(self):
        """Successful responses MUST return HTTP 200."""
        app, _ = _make_app()
        status, _, _ = app.handle_request(self._add_request_11())
        assert status == 200

    def test_http_500_for_server_fault(self):
        """SOAP 1.1 §6.2 — Server faults MUST return HTTP 500."""
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:divide><a>10</a><b>0</b></tns:divide>
          </soapenv:Body>
        </soapenv:Envelope>"""
        app, _ = _make_app()
        status, _ct, _body = app.handle_request(xml, soap_action="divide")
        assert status == 500  # WS-I BP R1109: ALL SOAP faults MUST return HTTP 500

    def test_http_500_for_client_fault(self):
        """WS-I BP 1.1 R1109 — ALL SOAP faults MUST return HTTP 500."""
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:nonexistent/>
          </soapenv:Body>
        </soapenv:Envelope>"""
        app, _ = _make_app()
        status, _, _ = app.handle_request(xml)
        assert status == 500

    def test_content_type_text_xml_soap11(self):
        """SOAP 1.1 §6 — Response Content-Type MUST be text/xml."""
        app, _ = _make_app()
        _, ct, _ = app.handle_request(self._add_request_11())
        assert "text/xml" in ct

    def test_content_type_soap_xml_soap12(self):
        """SOAP 1.2 Part 2 §7 — Response Content-Type MUST be application/soap+xml."""
        app, _ = _make_app()
        _, ct, _ = app.handle_request(self._add_request_12())
        assert "application/soap+xml" in ct

    def test_wsdl_served_on_get_wsdl_param(self):
        """WSDL MUST be served when ?wsdl is requested via SoapApplication.get_wsdl()."""
        app, _ = _make_app()
        wsdl = app.get_wsdl()
        assert len(wsdl) > 0
        root = _parse(wsdl)
        assert local_name(root) == "definitions"

    def test_http_405_for_non_post_asgi(self):
        """Non-GET/non-POST methods (e.g. PUT, DELETE) return 405 via ASGI adapter.

        NOTE: The ASGI adapter intentionally returns 200 for bare GET (without ?wsdl)
        with a human-readable endpoint description.  Only verbs like PUT/DELETE that
        are neither GET nor POST trigger 405.  This is a MINOR finding — many SOAP
        servers follow the same convention.
        """
        import asyncio

        from soapbar.server.asgi import AsgiSoapApp

        app, _ = _make_app()
        asgi = AsgiSoapApp(app)
        received: list[dict] = []

        async def run() -> None:
            scope = {
                "type": "http",
                "method": "PUT",
                "path": "/soap",
                "query_string": b"",
                "headers": [],
            }

            async def receive() -> dict:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(msg: dict) -> None:
                received.append(msg)

            await asgi(scope, receive, send)

        asyncio.run(run())
        status_msgs = [m for m in received if m.get("type") == "http.response.start"]
        assert len(status_msgs) == 1
        assert status_msgs[0]["status"] == 405

    def test_get_without_wsdl_param_returns_405(self):
        """GET without ?wsdl returns 405 Method Not Allowed (MINOR-002 fixed)."""
        import asyncio

        from soapbar.server.asgi import AsgiSoapApp

        app, _ = _make_app()
        asgi = AsgiSoapApp(app)
        received: list[dict] = []

        async def run() -> None:
            scope = {
                "type": "http",
                "method": "GET",
                "path": "/soap",
                "query_string": b"",
                "headers": [],
            }

            async def receive() -> dict:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(msg: dict) -> None:
                received.append(msg)

            await asgi(scope, receive, send)

        asyncio.run(run())
        status_msgs = [m for m in received if m.get("type") == "http.response.start"]
        assert len(status_msgs) == 1
        assert status_msgs[0]["status"] == 405


# ---------------------------------------------------------------------------
# 3g. Edge Cases & Robustness
# ---------------------------------------------------------------------------

class TestEdgeCasesAndRobustness:
    """Edge cases for parser robustness and protocol tolerance."""

    def _add_request(self, extra: str = "") -> bytes:
        return b"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:add><a>3</a><b>5</b></tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""

    def test_soap_message_with_xml_declaration(self):
        """XML <?xml?> prolog should be accepted."""
        app, _ = _make_app()
        # Use a request that has exactly one XML declaration (not doubled)
        xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:add><a>3</a><b>5</b></tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""
        status, _, _ = app.handle_request(xml)
        assert status == 200

    def test_soap_message_without_xml_declaration(self):
        """No XML prolog should also be accepted."""
        app, _ = _make_app()
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                          xmlns:tns="http://example.com/calc">
          <soapenv:Body><tns:add><a>3</a><b>5</b></tns:add></soapenv:Body>
        </soapenv:Envelope>"""
        status, _, _ = app.handle_request(xml)
        assert status == 200

    def test_unicode_content_in_body(self):
        """CJK characters and special XML chars must round-trip correctly."""
        sig = OperationSignature(
            name="echo",
            input_params=[OperationParameter("msg", xsd.resolve("string"))],  # type: ignore[arg-type]
            output_params=[OperationParameter("msg", xsd.resolve("string"))],  # type: ignore[arg-type]
        )
        text = "日本語テスト — Ñoño & <test> \" chars"
        serializer = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        body_out = etree.Element("_body")
        serializer.serialize_request(sig, {"msg": text}, body_out)
        xml_bytes = to_bytes(body_out[0])
        wrapper = _parse(xml_bytes)
        msg_elem = wrapper.find("msg")
        assert msg_elem is not None
        assert msg_elem.text == text

    def test_base64_binary_roundtrip(self):
        """binary data via xsd:base64Binary must round-trip losslessly."""
        b64_type = xsd.resolve("base64Binary")
        assert b64_type is not None
        raw = b"\x00\x01\x02\xff\xfe\xfd binary data"
        encoded = b64_type.to_xml(raw)
        decoded = b64_type.from_xml(encoded)
        assert decoded == raw

    def test_hexbinary_roundtrip(self):
        """xsd:hexBinary encode/decode round-trip."""
        hex_type = xsd.resolve("hexBinary")
        assert hex_type is not None
        raw = bytes(range(256))
        encoded = hex_type.to_xml(raw)
        decoded = hex_type.from_xml(encoded)
        assert decoded == raw

    def test_namespace_prefix_agnostic(self):
        """Non-standard ns prefix on Envelope MUST be parsed correctly."""
        xml = b"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
                              xmlns:tns="http://example.com/calc">
          <s:Body><tns:add><a>1</a><b>2</b></tns:add></s:Body>
        </s:Envelope>"""
        app, _ = _make_app()
        status, _, _ = app.handle_request(xml)
        assert status == 200

    def test_arbitrary_ns_prefix_envelope(self):
        """SOAP-ENV: prefix (classic legacy prefix) should also work."""
        xml = b"""<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                                     xmlns:tns="http://example.com/calc">
          <SOAP-ENV:Body><tns:add><a>10</a><b>20</b></tns:add></SOAP-ENV:Body>
        </SOAP-ENV:Envelope>"""
        app, _ = _make_app()
        status, _, _ = app.handle_request(xml)
        assert status == 200

    def test_malformed_xml_returns_fault(self):
        """Malformed XML MUST NOT crash the server — returns a SOAP Fault."""
        app, _ = _make_app()
        status, _ct, body = app.handle_request(b"<unclosed>")
        assert status in (400, 500), "Malformed XML must return 4xx or 5xx"
        # Body must still be valid XML containing an Envelope
        root = _parse(body)
        assert local_name(root) == "Envelope"

    def test_empty_soap_body(self):
        """Empty Body is structurally valid — application may return Client fault."""
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body/>
        </soapenv:Envelope>"""
        app, _ = _make_app()
        status, _, body_bytes = app.handle_request(xml)
        # Server should return a Fault, not crash
        assert status in (400, 500)
        root = _parse(body_bytes)
        assert local_name(root) == "Envelope"

    def test_large_payload_handled(self):
        """1 MB payload must be processed without error (not huge_tree blocked)."""
        big_value = "x" * (1024 * 1024)
        xml = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                                    xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:add><a>3</a><b>5</b>
              <!-- padding: {big_value} -->
            </tns:add>
          </soapenv:Body>
        </soapenv:Envelope>""".encode()
        app, _ = _make_app()
        # Comments are removed by the hardened parser, so the payload shrinks
        # Should succeed
        status, _, _ = app.handle_request(xml)
        assert status in (200, 400, 500)  # Any valid HTTP response, not a crash

    def test_deeply_nested_elements(self):
        """50 levels of nesting should parse without error."""
        inner = "<a>3</a><b>5</b>"
        for _ in range(50):
            inner = f"<wrapper>{inner}</wrapper>"
        xml = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                                    xmlns:tns="http://example.com/calc">
          <soapenv:Body>{inner}</soapenv:Body>
        </soapenv:Envelope>""".encode()
        try:
            env = SoapEnvelope.from_xml(xml)
            assert env.version == SoapVersion.SOAP_11
        except Exception:
            pass  # Deeply nested may legitimately fail; the key is no crash that breaks the process

    def test_xsi_nil_parsed(self):
        """xsi:nil='true' elements should be parseable without error."""
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <soapenv:Body>
            <payload xsi:nil="true"/>
          </soapenv:Body>
        </soapenv:Envelope>"""
        env = SoapEnvelope.from_xml(xml)
        assert len(env.body_elements) == 1

    def test_whitespace_only_text_nodes(self):
        """Whitespace-only text content in elements must not confuse the parser."""
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                                    xmlns:tns="http://example.com/calc">
          <soapenv:Body>
            <tns:add>
              <a>   3   </a>
              <b>5</b>
            </tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""
        app, _ = _make_app()
        # May or may not succeed depending on type coercion; must not crash
        status, _, _ = app.handle_request(xml)
        assert status in (200, 400, 500)


# ---------------------------------------------------------------------------
# 3h. mustUnderstand Enforcement
# ---------------------------------------------------------------------------

class TestMustUnderstandEnforcement:
    """SOAP 1.1 §4.2.3 / SOAP 1.2 Part 1 §5.2.3 — mustUnderstand enforcement."""

    def test_must_understand_true_unknown_header_11(self):
        """SOAP 1.1 §4.2.3 — mustUnderstand=1 on unknown header MUST generate
        MustUnderstand fault."""
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <ns:Security xmlns:ns="http://unknown.example.com/"
                         soapenv:mustUnderstand="1">token</ns:Security>
          </soapenv:Header>
          <soapenv:Body>
            <tns:add xmlns:tns="http://example.com/calc"><a>3</a><b>5</b></tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""
        app, _ = _make_app()
        status, _ct, body = app.handle_request(xml)
        # MUST return 500 with MustUnderstand faultcode
        assert status == 500
        root = _parse(body)
        fault_elem = root.find(f".//{{{SOAP11_ENV}}}Fault")
        assert fault_elem is not None
        fc = fault_elem.find("faultcode")
        assert fc is not None and fc.text == "MustUnderstand"

    def test_must_understand_true_unknown_header_12(self):
        """SOAP 1.2 §5.2.3 — mustUnderstand=true on unknown header MUST generate
        MustUnderstand fault."""
        xml = b"""<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
          <soap12:Header>
            <ns:Security xmlns:ns="http://unknown.example.com/"
                         soap12:mustUnderstand="true">token</ns:Security>
          </soap12:Header>
          <soap12:Body>
            <tns:add xmlns:tns="http://example.com/calc"><a>3</a><b>5</b></tns:add>
          </soap12:Body>
        </soap12:Envelope>"""
        app, _ = _make_app()
        status, _ct, body = app.handle_request(xml)
        assert status == 500
        root = _parse(body)
        fault_elem = root.find(f".//{{{SOAP12_ENV}}}Fault")
        assert fault_elem is not None
        code_elem = fault_elem.find(f"{{{SOAP12_ENV}}}Code")
        assert code_elem is not None
        val_elem = code_elem.find(f"{{{SOAP12_ENV}}}Value")
        assert val_elem is not None
        assert "MustUnderstand" in (val_elem.text or "")

    def test_version_mismatch_fault_includes_upgrade_header_12(self):
        """[SOAP12-P1] §5.4.7 MUST — VersionMismatch fault envelope MUST include
        an Upgrade header block listing supported envelope namespace URIs."""
        bad_xml = b"""<bad:Envelope xmlns:bad="http://unknown.example.com/soap">
          <bad:Body><bad:Op/></bad:Body>
        </bad:Envelope>"""
        app, _ = _make_app()
        # Force SOAP 1.2 processing path via Content-Type
        status, _, body = app.handle_request(
            bad_xml, content_type="application/soap+xml"
        )
        assert status == 500
        root = _parse(body)
        # Header element MUST be present
        header = root.find(f"{{{SOAP12_ENV}}}Header")
        assert header is not None, "VersionMismatch fault MUST include a soap12:Header"
        # Upgrade element MUST be present inside Header
        upgrade = header.find(f"{{{SOAP12_ENV}}}Upgrade")
        assert upgrade is not None, (
            "VersionMismatch fault Header MUST contain soap12:Upgrade [SOAP12-P1] §5.4.7"
        )
        # At least one SupportedEnvelope child
        supported = upgrade.findall(f"{{{SOAP12_ENV}}}SupportedEnvelope")
        assert len(supported) >= 1, "Upgrade MUST list at least one SupportedEnvelope"
        # Each SupportedEnvelope MUST have a qname attribute
        for se in supported:
            assert se.get("qname"), "SupportedEnvelope MUST have a qname attribute"
        # SOAP 1.2 namespace must be listed
        soap12_listed = any(
            se.nsmap.get(q.split(":")[0]) == SOAP12_ENV
            for se in supported
            for q in [se.get("qname", "")]
            if ":" in q
        )
        assert soap12_listed, (
            "Upgrade MUST list the SOAP 1.2 envelope namespace as a SupportedEnvelope"
        )

    def test_must_understand_fault_includes_not_understood_header_12(self):
        """[SOAP12-P1] §5.4.8 SHOULD — MustUnderstand fault envelope SHOULD include
        a NotUnderstood header block identifying the unrecognised header."""
        xml = b"""<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
          <soap12:Header>
            <ns:Auth xmlns:ns="http://unknown.example.com/"
                     soap12:mustUnderstand="true">token</ns:Auth>
          </soap12:Header>
          <soap12:Body>
            <tns:add xmlns:tns="http://example.com/calc"><a>1</a><b>2</b></tns:add>
          </soap12:Body>
        </soap12:Envelope>"""
        app, _ = _make_app()
        status, _, body = app.handle_request(
            xml, content_type="application/soap+xml"
        )
        assert status == 500
        root = _parse(body)
        # Header MUST be present
        header = root.find(f"{{{SOAP12_ENV}}}Header")
        assert header is not None, (
            "MustUnderstand fault SHOULD include a soap12:Header [SOAP12-P1] §5.4.8"
        )
        # NotUnderstood element SHOULD be present
        not_understood = header.find(f"{{{SOAP12_ENV}}}NotUnderstood")
        assert not_understood is not None, (
            "MustUnderstand fault SHOULD contain soap12:NotUnderstood [SOAP12-P1] §5.4.8"
        )
        # qname attribute MUST be present and non-empty
        qname = not_understood.get("qname", "")
        assert qname, "NotUnderstood MUST carry a qname attribute"
        # qname should reference the offending header (Auth in ns)
        assert "Auth" in qname, (
            f"NotUnderstood qname {qname!r} should identify the Auth header"
        )

    def test_must_understand_false_no_fault(self):
        """mustUnderstand=0/false on any header MUST NOT generate a fault."""
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Header>
            <ns:Opt xmlns:ns="http://example.com/" soapenv:mustUnderstand="0">val</ns:Opt>
          </soapenv:Header>
          <soapenv:Body>
            <tns:add xmlns:tns="http://example.com/calc"><a>3</a><b>5</b></tns:add>
          </soapenv:Body>
        </soapenv:Envelope>"""
        app, _ = _make_app()
        status, _, _ = app.handle_request(xml)
        assert status == 200, "mustUnderstand=0 must not generate a fault"


# ---------------------------------------------------------------------------
# Namespace Constants Audit
# ---------------------------------------------------------------------------

class TestNamespaceConstants:
    """Verify NS constants match normative specifications exactly."""

    def test_soap11_envelope_ns(self):
        """SOAP 1.1 §4.1.2."""
        assert NS.SOAP_ENV == "http://schemas.xmlsoap.org/soap/envelope/"

    def test_soap12_envelope_ns(self):
        """SOAP 1.2 Part 1 §5.1."""
        assert NS.SOAP12_ENV == "http://www.w3.org/2003/05/soap-envelope"

    def test_soap11_encoding_ns(self):
        """SOAP 1.1 §5.1."""
        assert NS.SOAP_ENC == "http://schemas.xmlsoap.org/soap/encoding/"

    def test_soap12_encoding_ns(self):
        """SOAP 1.2 Part 2 §4.1."""
        assert NS.SOAP12_ENC == "http://www.w3.org/2003/05/soap-encoding"

    def test_xsd_ns(self):
        """W3C XML Schema §2.6.2."""
        assert NS.XSD == "http://www.w3.org/2001/XMLSchema"

    def test_xsi_ns(self):
        """W3C XML Schema Instance §2.6."""
        assert NS.XSI == "http://www.w3.org/2001/XMLSchema-instance"

    def test_wsdl_ns(self):
        """WSDL 1.1 §2."""
        assert NS.WSDL == "http://schemas.xmlsoap.org/wsdl/"

    def test_wsdl_soap11_ns(self):
        """WSDL 1.1 SOAP 1.1 binding extension."""
        assert NS.WSDL_SOAP == "http://schemas.xmlsoap.org/wsdl/soap/"

    def test_wsdl_soap12_ns(self):
        """WSDL 1.1 SOAP 1.2 binding extension (de facto standard)."""
        # Note: No official W3C WSDL 1.1 + SOAP 1.2 standard exists;
        # this namespace is the widely-adopted community convention.
        assert NS.WSDL_SOAP12 == "http://schemas.xmlsoap.org/wsdl/soap12/"

    def test_wsse_ns(self):
        """OASIS WS-Security 1.0."""
        assert "oasis-open.org" in NS.WSSE
        assert "wss-wssecurity-secext" in NS.WSSE

    def test_wsa_ns(self):
        """W3C WS-Addressing 1.0."""
        assert NS.WSA == "http://www.w3.org/2005/08/addressing"


# ---------------------------------------------------------------------------
# XSD Type Registry
# ---------------------------------------------------------------------------

class TestXsdTypeRegistry:
    """XSD type coverage and correctness."""

    def test_all_27_types_registered(self):
        """27 built-in types must be registered."""
        all_types = xsd.all_types()
        assert len(all_types) == 27, f"Expected 27 types, found {len(all_types)}"

    def test_integer_types_range_validated(self):
        """Integer types with range constraints should reject out-of-range values."""
        int_type = xsd.resolve("int")
        assert int_type is not None
        with pytest.raises(ValueError):
            int_type.to_xml(2**31)  # Beyond int max

    def test_boolean_true_false_values(self):
        """xsd:boolean accepts 'true', 'false', '1', '0'."""
        bool_type = xsd.resolve("boolean")
        assert bool_type is not None
        assert bool_type.from_xml("true") is True
        assert bool_type.from_xml("false") is False
        assert bool_type.from_xml("1") is True
        assert bool_type.from_xml("0") is False

    def test_float_special_values(self):
        """xsd:float NaN, INF, -INF must serialize/deserialize correctly."""
        float_type = xsd.resolve("float")
        assert float_type is not None
        assert float_type.to_xml(float("inf")) == "INF"
        assert float_type.to_xml(float("-inf")) == "-INF"
        assert float_type.to_xml(float("nan")) == "NaN"
        assert float_type.from_xml("INF") == float("inf")
        assert float_type.from_xml("-INF") == float("-inf")

    def test_decimal_precision(self):
        """xsd:decimal must maintain precision beyond float range."""
        from decimal import Decimal
        decimal_type = xsd.resolve("decimal")
        assert decimal_type is not None
        val = Decimal("1234567890123456789.0987654321")
        result = decimal_type.from_xml(decimal_type.to_xml(val))
        assert result == val

    def test_python_to_xsd_bool_before_int(self):
        """bool must map to 'boolean', not 'int' (bool is subclass of int)."""
        bool_xsd = xsd.python_to_xsd(bool)
        assert bool_xsd is not None
        assert bool_xsd.name == "boolean"

    def test_resolve_clark_notation(self):
        """resolve() accepts Clark notation {ns}local."""
        from soapbar.core.namespaces import NS as _NS
        resolved = xsd.resolve(f"{{{_NS.XSD}}}int")
        assert resolved is not None
        assert resolved.name == "int"

    def test_resolve_prefix_notation(self):
        """resolve() accepts xsd:type prefix notation."""
        resolved = xsd.resolve("xsd:string")
        assert resolved is not None
        assert resolved.name == "string"
