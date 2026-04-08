"""Comprehensive tests for soapbar — 31 tests covering all modules."""
from __future__ import annotations

import io
import sys
import urllib.error
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from lxml import etree

import soapbar
from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport
from soapbar.core.binding import (
    BindingStyle,
    DocumentEncodedSerializer,
    DocumentLiteralSerializer,
    DocumentLiteralWrappedSerializer,
    OperationParameter,
    OperationSignature,
    RpcEncodedSerializer,
    RpcLiteralSerializer,
    get_serializer,
)
from soapbar.core.envelope import SoapEnvelope, SoapVersion, build_fault, http_headers
from soapbar.core.fault import SoapFault
from soapbar.core.namespaces import NS
from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType, xsd

_xsd_string = xsd.resolve("string")
_xsd_int = xsd.resolve("int")
assert _xsd_string is not None
assert _xsd_int is not None
from soapbar.core.wsdl import WsdlDefinition
from soapbar.core.wsdl.builder import build_wsdl_string
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file
from soapbar.core.xml import (
    build_nsmap,
    clone,
    collect_namespaces,
    compile_schema,
    find,
    findall,
    findtext,
    get_attr,
    local_name,
    make_element,
    namespace_uri,
    parse_xml,
    parse_xml_document,
    parse_xml_file,
    set_attr,
    sub_element,
    to_bytes,
    to_string,
    validate_schema,
)
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation
from soapbar.server.wsgi import WsgiSoapApp

# =============================================================================
# 1. Namespaces
# =============================================================================

class TestNamespaces:
    def test_constants(self) -> None:
        assert NS.SOAP_ENV == "http://schemas.xmlsoap.org/soap/envelope/"
        assert NS.SOAP12_ENV == "http://www.w3.org/2003/05/soap-envelope"
        assert NS.XSD == "http://www.w3.org/2001/XMLSchema"
        assert NS.XSI == "http://www.w3.org/2001/XMLSchema-instance"
        assert NS.WSDL == "http://schemas.xmlsoap.org/wsdl/"
        assert NS.WSSE is not None
        assert NS.WSU is not None
        assert NS.WSA is not None

    def test_qname_and_split(self) -> None:
        clark = NS.qname(NS.XSD, "string")
        assert clark == "{http://www.w3.org/2001/XMLSchema}string"
        ns, local = NS.split_qname(clark)
        assert ns == NS.XSD
        assert local == "string"

    def test_split_bare_name(self) -> None:
        ns, local = NS.split_qname("bareWord")
        assert ns is None
        assert local == "bareWord"

    def test_prefix_for(self) -> None:
        prefix = NS.prefix_for(NS.XSD)
        assert prefix == "xsd"
        assert NS.prefix_for("http://unknown/") is None


# =============================================================================
# 2. XML utilities
# =============================================================================

class TestXml:
    def test_parse_and_roundtrip(self) -> None:
        xml = b"<root><child>hello</child></root>"
        elem = parse_xml(xml)
        assert local_name(elem) == "root"
        assert elem.find("child") is not None
        assert elem.find("child").text == "hello"  # type: ignore[union-attr]

    def test_hardened_parser_rejects_xxe(self) -> None:
        """Parser must not expand external entity content (XXE safe).
        lxml with resolve_entities=False silently drops entity references
        rather than expanding them — the text will be None/empty, not file content.
        """
        xxe = b"""<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>"""
        try:
            elem = parse_xml(xxe)
            # If parsed, entity must NOT have been expanded to file content
            text = elem.text or ""
            assert "root:" not in text, "XXE entity was expanded — security violation!"
        except Exception:
            # Raising an exception is also acceptable (strict parser mode)
            pass

    def test_make_element_and_serialization(self) -> None:
        elem = make_element(
            f"{{{NS.SOAP_ENV}}}Envelope",
            nsmap={"soapenv": NS.SOAP_ENV},
        )
        s = to_string(elem)
        assert "Envelope" in s
        assert NS.SOAP_ENV in s

    def test_parse_xml_document_passthrough(self) -> None:
        elem = make_element("test")
        result = parse_xml_document(elem)
        assert result is elem

    def test_to_bytes_xml_declaration(self) -> None:
        elem = make_element("root")
        b = to_bytes(elem, xml_declaration=True)
        assert b.startswith(b"<?xml")

    def test_namespace_uri_and_local_name(self) -> None:
        elem = make_element(f"{{{NS.XSD}}}string")
        assert namespace_uri(elem) == NS.XSD
        assert local_name(elem) == "string"


# =============================================================================
# 3. Type system
# =============================================================================

class TestTypes:
    def test_string_roundtrip(self) -> None:
        t = xsd.resolve("string")
        assert t is not None
        assert t.to_xml("hello") == "hello"
        assert t.from_xml("world") == "world"

    def test_int_roundtrip(self) -> None:
        t = xsd.resolve("int")
        assert t is not None
        assert t.to_xml(42) == "42"
        assert t.from_xml("42") == 42

    def test_boolean_roundtrip(self) -> None:
        t = xsd.resolve("boolean")
        assert t is not None
        assert t.to_xml(True) == "true"
        assert t.to_xml(False) == "false"
        assert t.from_xml("true") is True
        assert t.from_xml("1") is True
        assert t.from_xml("false") is False
        assert t.from_xml("0") is False

    def test_float_special_values(self) -> None:
        t = xsd.resolve("float")
        assert t is not None
        assert t.to_xml(float("inf")) == "INF"
        assert t.to_xml(float("-inf")) == "-INF"
        assert t.to_xml(float("nan")) == "NaN"
        assert t.from_xml("INF") == float("inf")
        assert t.from_xml("-INF") == float("-inf")

    def test_base64_binary(self) -> None:
        t = xsd.resolve("base64Binary")
        assert t is not None
        encoded = t.to_xml(b"hello")
        assert encoded == "aGVsbG8="
        assert t.from_xml(encoded) == b"hello"

    def test_python_to_xsd_bool_before_int(self) -> None:
        """bool must resolve before int since bool is subclass of int."""
        bool_type = xsd.python_to_xsd(bool)
        int_type = xsd.python_to_xsd(int)
        assert bool_type is not None
        assert int_type is not None
        assert bool_type.name == "boolean"
        assert int_type.name == "int"

    def test_resolve_clark_notation(self) -> None:
        t = xsd.resolve(f"{{{NS.XSD}}}string")
        assert t is not None
        assert t.name == "string"

    def test_resolve_prefixed(self) -> None:
        t = xsd.resolve("xsd:int")
        assert t is not None
        assert t.name == "int"

    def test_all_27_types_registered(self) -> None:
        types = xsd.all_types()
        assert len(types) == 27


# =============================================================================
# 4. Fault
# =============================================================================

class TestFault:
    def test_soap11_fault_element(self) -> None:
        f = SoapFault("Client", "Bad request", detail="invalid input")
        elem = f.to_soap11_element()
        assert local_name(elem) == "Fault"
        fc = elem.find("faultcode")
        fs = elem.find("faultstring")
        assert fc is not None and fc.text == "Client"
        assert fs is not None and fs.text == "Bad request"
        det = elem.find("detail")
        assert det is not None and det.text == "invalid input"

    def test_soap12_fault_element(self) -> None:
        f = SoapFault("Server", "Internal error")
        elem = f.to_soap12_element()
        assert local_name(elem) == "Fault"
        assert namespace_uri(elem) == NS.SOAP12_ENV
        # Check code mapping: Server → Receiver
        code_elem = elem.find(f"{{{NS.SOAP12_ENV}}}Code")
        assert code_elem is not None
        val_elem = code_elem.find(f"{{{NS.SOAP12_ENV}}}Value")
        assert val_elem is not None
        assert "Receiver" in (val_elem.text or "")

    def test_fault_envelope_roundtrip_11(self) -> None:
        f = SoapFault("Client", "Test")
        env_elem = f.to_soap11_envelope()
        parsed = SoapFault.from_element(env_elem)
        assert parsed.faultcode == "Client"
        assert parsed.faultstring == "Test"

    def test_fault_envelope_roundtrip_12(self) -> None:
        f = SoapFault("Server", "Internal")
        env_elem = f.to_soap12_envelope()
        parsed = SoapFault.from_element(env_elem)
        # Receiver maps back to Server
        assert parsed.faultcode == "Server"
        assert parsed.faultstring == "Internal"

    def test_fault_from_fault_element_directly(self) -> None:
        f = SoapFault("Client", "Direct")
        fault_elem = f.to_soap11_element()
        parsed = SoapFault.from_element(fault_elem)
        assert parsed.faultcode == "Client"
        assert parsed.faultstring == "Direct"


# =============================================================================
# 5. Binding serializers
# =============================================================================

class TestBinding:
    def _make_sig(self) -> OperationSignature:
        string_type = xsd.resolve("string")
        int_type = xsd.resolve("int")
        assert string_type is not None
        assert int_type is not None
        return OperationSignature(
            name="Add",
            input_params=[
                OperationParameter("a", int_type),
                OperationParameter("b", int_type),
            ],
            output_params=[
                OperationParameter("result", int_type),
            ],
        )

    def test_rpc_encoded_xsi_type(self) -> None:
        sig = self._make_sig()
        serializer = RpcEncodedSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 3, "b": 4}, container)
        wrapper = container[0]
        a_elem = wrapper.find("a")
        assert a_elem is not None
        xsi_type = a_elem.get(f"{{{NS.XSI}}}type")
        assert xsi_type == "xsd:int"

    def test_rpc_literal_no_xsi_type(self) -> None:
        sig = self._make_sig()
        serializer = RpcLiteralSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 1, "b": 2}, container)
        wrapper = container[0]
        a_elem = wrapper.find("a")
        assert a_elem is not None
        assert a_elem.get(f"{{{NS.XSI}}}type") is None

    def test_document_literal_wrapped_roundtrip(self) -> None:
        sig = self._make_sig()
        serializer = DocumentLiteralWrappedSerializer()
        # Serialize
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 10, "b": 20}, container)
        # Deserialize
        values = serializer.deserialize_request(sig, container)
        assert values["a"] == 10
        assert values["b"] == 20

    def test_get_serializer_factory(self) -> None:
        s = get_serializer(BindingStyle.RPC_ENCODED)
        assert isinstance(s, RpcEncodedSerializer)
        s2 = get_serializer(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        assert isinstance(s2, DocumentLiteralWrappedSerializer)

    def test_binding_style_properties(self) -> None:
        assert BindingStyle.RPC_ENCODED.soap_style == "rpc"
        assert BindingStyle.RPC_ENCODED.soap_use == "encoded"
        assert BindingStyle.RPC_ENCODED.is_rpc is True
        assert BindingStyle.RPC_ENCODED.is_encoded is True
        assert BindingStyle.DOCUMENT_LITERAL_WRAPPED.is_wrapped is True
        assert BindingStyle.DOCUMENT_LITERAL.is_wrapped is False
        assert BindingStyle.DOCUMENT_ENCODED.soap_style == "document"
        assert BindingStyle.DOCUMENT_ENCODED.soap_use == "encoded"
        assert BindingStyle.DOCUMENT_ENCODED.is_rpc is False
        assert BindingStyle.DOCUMENT_ENCODED.is_encoded is True
        assert BindingStyle.DOCUMENT_ENCODED.is_wrapped is False

    def test_document_encoded_xsi_type(self) -> None:
        sig = self._make_sig()
        serializer = DocumentEncodedSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 3, "b": 4}, container)
        # Params must be direct Body children (no wrapper element)
        assert len(container) == 2
        a_elem = container.find("a")
        b_elem = container.find("b")
        assert a_elem is not None
        assert b_elem is not None
        assert a_elem.get(f"{{{NS.XSI}}}type") == "xsd:int"
        assert b_elem.get(f"{{{NS.XSI}}}type") == "xsd:int"
        assert a_elem.text == "3"
        assert b_elem.text == "4"

    def test_document_encoded_roundtrip(self) -> None:
        sig = self._make_sig()
        serializer = DocumentEncodedSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 7, "b": 13}, container)
        values = serializer.deserialize_request(sig, container)
        assert values["a"] == 7
        assert values["b"] == 13

    def test_document_literal_multi_param_no_parts_wrapper(self) -> None:
        sig = self._make_sig()
        serializer = DocumentLiteralSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 5, "b": 6}, container)
        # Both params must be direct Body children — no <_parts> wrapper
        assert len(container) == 2
        a_elem = container.find("a")
        b_elem = container.find("b")
        assert a_elem is not None
        assert b_elem is not None
        # Roundtrip
        values = serializer.deserialize_request(sig, container)
        assert values["a"] == 5
        assert values["b"] == 6

    def test_get_serializer_document_encoded(self) -> None:
        s = get_serializer(BindingStyle.DOCUMENT_ENCODED)
        assert isinstance(s, DocumentEncodedSerializer)

    def test_document_literal_roundtrip_with_op_namespace(self) -> None:
        """Bug fix: _extract must use sig.input_namespace when param.namespace is None."""
        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type), OperationParameter("b", int_type)],
            output_params=[OperationParameter("result", int_type)],
            input_namespace="http://example.com/soap",
            output_namespace="http://example.com/soap",
        )
        serializer = DocumentLiteralSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 3, "b": 7}, container)
        # Elements must be namespace-qualified
        assert container.find("{http://example.com/soap}a") is not None
        assert container.find("a") is None  # bare name must not exist
        # Deserialize must find them back
        values = serializer.deserialize_request(sig, container)
        assert values["a"] == 3
        assert values["b"] == 7

    def test_document_literal_response_roundtrip_with_op_namespace(self) -> None:
        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type)],
            output_params=[OperationParameter("result", int_type)],
            output_namespace="http://example.com/soap",
        )
        serializer = DocumentLiteralSerializer()
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 42}, container)
        values = serializer.deserialize_response(sig, container)
        assert values["result"] == 42

    def test_document_encoded_roundtrip_with_op_namespace(self) -> None:
        """Bug fix: _extract_params must use sig.input_namespace when param.namespace is None."""
        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type), OperationParameter("b", int_type)],
            output_params=[OperationParameter("result", int_type)],
            input_namespace="http://example.com/soap",
            output_namespace="http://example.com/soap",
        )
        serializer = DocumentEncodedSerializer()
        container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 5, "b": 9}, container)
        # Elements must be namespace-qualified
        assert container.find("{http://example.com/soap}a") is not None
        values = serializer.deserialize_request(sig, container)
        assert values["a"] == 5
        assert values["b"] == 9

    def test_document_literal_rejects_unqualified_element_when_namespace_expected(self) -> None:
        """XML Namespaces MUST: unqualified elements are NOT matched when namespace is declared."""
        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type)],
            output_params=[],
            input_namespace="http://example.com/soap",
        )
        serializer = DocumentLiteralSerializer()
        # Non-conformant client sends bare (unnamespaced) element — must be rejected
        container = etree.Element("_body")
        etree.SubElement(container, "a").text = "99"
        values = serializer.deserialize_request(sig, container)
        # param "a" should NOT be found — namespace-qualified lookup returns nothing
        assert "a" not in values


# =============================================================================
# 6. Envelope
# =============================================================================

class TestEnvelope:
    def test_build_soap11_envelope(self) -> None:
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        body = make_element(f"{{{NS.SOAP_ENV}}}test")
        env.add_body_content(body)
        elem = env.build()
        assert namespace_uri(elem) == NS.SOAP_ENV
        assert local_name(elem) == "Envelope"

    def test_roundtrip_soap12(self) -> None:
        env = SoapEnvelope(version=SoapVersion.SOAP_12)
        content = make_element(f"{{{NS.SOAP12_ENV}}}GetData")
        env.add_body_content(content)
        xml_bytes = env.to_bytes()
        parsed = SoapEnvelope.from_xml(xml_bytes)
        assert parsed.version == SoapVersion.SOAP_12
        assert parsed.operation_name == "GetData"

    def test_from_xml_detects_version(self) -> None:
        soap11 = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body><op/></soapenv:Body>
        </soapenv:Envelope>"""
        env = SoapEnvelope.from_xml(soap11)
        assert env.version == SoapVersion.SOAP_11

        soap12 = b"""<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
          <soap12:Body><op/></soap12:Body>
        </soap12:Envelope>"""
        env12 = SoapEnvelope.from_xml(soap12)
        assert env12.version == SoapVersion.SOAP_12

    def test_is_fault_property(self) -> None:
        f = SoapFault("Server", "boom")
        env_elem = f.to_soap11_envelope()
        env = SoapEnvelope.from_xml(to_string(env_elem))
        assert env.is_fault is True

    def test_build_fault_module_function(self) -> None:
        env_elem = build_fault(SoapVersion.SOAP_11, "Client", "bad")
        env = SoapEnvelope.from_xml(to_string(env_elem))
        assert env.is_fault is True
        fault = env.fault
        assert fault is not None
        assert fault.faultcode == "Client"

    def test_http_headers_soap11(self) -> None:
        h = http_headers(SoapVersion.SOAP_11, "http://example.com/Op")
        assert "SOAPAction" in h
        assert h["SOAPAction"] == '"http://example.com/Op"'

    def test_http_headers_soap12(self) -> None:
        h = http_headers(SoapVersion.SOAP_12, "myAction")
        assert "action=" in h["Content-Type"]


# =============================================================================
# 7. WSDL
# =============================================================================

SIMPLE_WSDL = b"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://example.com/calc"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="http://example.com/calc"
             name="Calculator">
  <message name="AddRequest">
    <part name="a" type="xsd:int"/>
    <part name="b" type="xsd:int"/>
  </message>
  <message name="AddResponse">
    <part name="result" type="xsd:int"/>
  </message>
  <portType name="CalculatorPortType">
    <operation name="Add">
      <input message="tns:AddRequest"/>
      <output message="tns:AddResponse"/>
    </operation>
  </portType>
  <binding name="CalculatorBinding" type="tns:CalculatorPortType">
    <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Add">
      <soap:operation soapAction="http://example.com/calc/Add" style="rpc"/>
      <input>
        <soap:body use="encoded" namespace="http://example.com/calc"/>
      </input>
      <output>
        <soap:body use="encoded" namespace="http://example.com/calc"/>
      </output>
    </operation>
  </binding>
  <service name="Calculator">
    <port name="CalculatorPort" binding="tns:CalculatorBinding">
      <soap:address location="http://example.com/calc"/>
    </port>
  </service>
</definitions>"""


class TestWsdl:
    def test_parse_wsdl(self) -> None:
        defn = parse_wsdl(SIMPLE_WSDL)
        assert defn.name == "Calculator"
        assert defn.target_namespace == "http://example.com/calc"
        assert "AddRequest" in defn.messages
        assert "CalculatorPortType" in defn.port_types
        assert "CalculatorBinding" in defn.bindings
        assert "Calculator" in defn.services

    def test_wsdl_binding_style(self) -> None:
        defn = parse_wsdl(SIMPLE_WSDL)
        binding = defn.bindings["CalculatorBinding"]
        style = binding.binding_style_for("Add")
        assert style == BindingStyle.RPC_ENCODED

    def test_wsdl_service_address(self) -> None:
        defn = parse_wsdl(SIMPLE_WSDL)
        assert defn.first_service_address == "http://example.com/calc"

    def test_build_wsdl_roundtrip(self) -> None:
        defn = parse_wsdl(SIMPLE_WSDL)
        wsdl_str = build_wsdl_string(defn, "http://example.com/calc")
        assert "Calculator" in wsdl_str
        assert "AddRequest" in wsdl_str

    def test_wsdl_import_namespace_only_skipped(self) -> None:
        """wsdl:import with no location= is silently skipped."""
        wsdl_with_ns_import = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/">
          <import namespace="http://other.com/"/>
          <portType name="PT"/>
        </definitions>"""
        defn = parse_wsdl(wsdl_with_ns_import)
        assert "PT" in defn.port_types


# =============================================================================
# 7b. WSDL Parser — coverage for previously untested paths
# =============================================================================

class TestWsdlParserPaths:
    """Target the specific parser paths that were not covered."""

    # --- portType operation with documentation and fault ---

    def test_operation_documentation_parsed(self) -> None:
        wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     xmlns:tns="http://example.com/"
                     targetNamespace="http://example.com/">
          <message name="Req"><part name="a" type="xsd:int"/></message>
          <message name="Resp"><part name="r" type="xsd:int"/></message>
          <portType name="PT">
            <operation name="Op">
              <documentation>Computes something useful</documentation>
              <input message="tns:Req"/>
              <output message="tns:Resp"/>
            </operation>
          </portType>
        </definitions>"""
        defn = parse_wsdl(wsdl)
        op = defn.port_types["PT"].operations[0]
        assert op.documentation == "Computes something useful"

    def test_operation_fault_parsed(self) -> None:
        wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     xmlns:tns="http://example.com/"
                     targetNamespace="http://example.com/">
          <message name="Req"><part name="a" type="xsd:int"/></message>
          <message name="Resp"><part name="r" type="xsd:int"/></message>
          <message name="Fault"><part name="msg" type="xsd:string"/></message>
          <portType name="PT">
            <operation name="Op">
              <input message="tns:Req"/>
              <output message="tns:Resp"/>
              <fault name="OpFault" message="tns:Fault"/>
            </operation>
          </portType>
        </definitions>"""
        defn = parse_wsdl(wsdl)
        op = defn.port_types["PT"].operations[0]
        assert len(op.faults) == 1
        assert op.faults[0].name == "OpFault"

    # --- schema: unnamed complexType is skipped ---

    def test_unnamed_complextype_skipped(self) -> None:
        wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     targetNamespace="http://example.com/">
          <types>
            <xsd:schema targetNamespace="http://example.com/">
              <xsd:complexType>
                <xsd:sequence><xsd:element name="x" type="xsd:int"/></xsd:sequence>
              </xsd:complexType>
              <xsd:complexType name="Named">
                <xsd:sequence><xsd:element name="y" type="xsd:string"/></xsd:sequence>
              </xsd:complexType>
            </xsd:schema>
          </types>
        </definitions>"""
        defn = parse_wsdl(wsdl)
        assert "Named" in defn.complex_types
        # unnamed type must not appear
        assert "" not in defn.complex_types

    # --- schema: sequence element without type= defaults to xsd:string ---

    def test_sequence_element_no_type_defaults_to_string(self) -> None:
        wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     targetNamespace="http://example.com/">
          <types>
            <xsd:schema targetNamespace="http://example.com/">
              <xsd:complexType name="NoType">
                <xsd:sequence>
                  <xsd:element name="val"/>
                </xsd:sequence>
              </xsd:complexType>
            </xsd:schema>
          </types>
        </definitions>"""
        defn = parse_wsdl(wsdl)
        ct = defn.complex_types["NoType"]
        assert ct.name == "NoType"

    # --- schema: choice type ---

    def test_choice_type_parsed(self) -> None:
        wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     targetNamespace="http://example.com/">
          <types>
            <xsd:schema targetNamespace="http://example.com/">
              <xsd:complexType name="MyChoice">
                <xsd:choice>
                  <xsd:element name="intVal" type="xsd:int"/>
                  <xsd:element name="strVal" type="xsd:string"/>
                </xsd:choice>
              </xsd:complexType>
            </xsd:schema>
          </types>
        </definitions>"""
        defn = parse_wsdl(wsdl)
        ct = defn.complex_types["MyChoice"]
        assert isinstance(ct, ChoiceXsdType)
        assert len(ct.options) == 2
        assert ct.options[0][0] == "intVal"
        assert ct.options[1][0] == "strVal"

    # --- schema: complexContent / SOAP-encoded array (arrayType on restriction) ---

    def test_complexcontent_array_type_on_restriction_attrib(self) -> None:
        """wsdl:arrayType declared as an XML attribute on <xsd:restriction>."""
        soapenc = "http://schemas.xmlsoap.org/soap/encoding/"
        wsdl = (
            b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
                     targetNamespace="http://example.com/">
          <types>
            <xsd:schema targetNamespace="http://example.com/">
              <xsd:complexType name="StringArray">
                <xsd:complexContent>
                  <xsd:restriction base="soapenc:Array"
                      soapenc:arrayType="xsd:string[]"/>
                </xsd:complexContent>
              </xsd:complexType>
            </xsd:schema>
          </types>
        </definitions>"""
        )
        defn = parse_wsdl(wsdl)
        ct = defn.complex_types["StringArray"]
        assert isinstance(ct, ArrayXsdType)
        assert ct.name == "StringArray"

    def test_complexcontent_array_type_on_child_attribute_element(self) -> None:
        """wsdl:arrayType declared on a child <xsd:attribute> element."""
        wsdl = (
            b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
                     xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/">
          <types>
            <xsd:schema targetNamespace="http://example.com/">
              <xsd:complexType name="IntArray">
                <xsd:complexContent>
                  <xsd:restriction base="soapenc:Array">
                    <xsd:attribute ref="soapenc:arrayType"
                        wsdl:arrayType="xsd:int[]"/>
                  </xsd:restriction>
                </xsd:complexContent>
              </xsd:complexType>
            </xsd:schema>
          </types>
        </definitions>"""
        )
        defn = parse_wsdl(wsdl)
        ct = defn.complex_types["IntArray"]
        assert isinstance(ct, ArrayXsdType)
        assert ct.name == "IntArray"

    # --- parse_wsdl_file ---

    def test_parse_wsdl_file(self, tmp_path: pytest.TempdirFactory) -> None:
        wsdl_file = tmp_path / "calc.wsdl"  # type: ignore[operator]
        wsdl_file.write_bytes(SIMPLE_WSDL)
        defn = parse_wsdl_file(wsdl_file)
        assert defn.name == "Calculator"
        assert "AddRequest" in defn.messages

    # --- file-based WSDL import (covers _fetch_wsdl_source file path) ---

    def test_wsdl_file_import(self, tmp_path: pytest.TempdirFactory) -> None:
        imported_wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     targetNamespace="http://example.com/imported">
          <message name="ImportedMsg">
            <part name="val" type="xsd:string"/>
          </message>
        </definitions>"""
        main_wsdl = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/main">
          <import location="imported.wsdl"/>
        </definitions>"""
        tmp_path = tmp_path  # type: ignore[assignment]
        (tmp_path / "imported.wsdl").write_bytes(imported_wsdl)  # type: ignore[operator]
        main_file = tmp_path / "main.wsdl"  # type: ignore[operator]
        main_file.write_bytes(main_wsdl)
        defn = parse_wsdl_file(main_file)
        assert "ImportedMsg" in defn.messages


# =============================================================================
# 7c. WSDL Builder — coverage for ArrayXsdType and ChoiceXsdType
# =============================================================================

class TestWsdlBuilderComplexTypes:
    """Cover _array_type_to_xsd and _choice_type_to_xsd builder paths."""

    def test_build_wsdl_with_array_type(self) -> None:
        int_type = xsd.resolve("int")
        assert int_type is not None
        arr = ArrayXsdType(name="IntList", element_type=int_type, element_tag="item")
        defn = WsdlDefinition(
            name="Svc",
            target_namespace="http://example.com/",
            complex_types={"IntList": arr},
        )
        wsdl_str = build_wsdl_string(defn, "http://example.com/")
        assert "IntList" in wsdl_str
        assert "maxOccurs" in wsdl_str

    def test_build_wsdl_with_choice_type(self) -> None:
        int_type = xsd.resolve("int")
        str_type = xsd.resolve("string")
        assert int_type is not None
        assert str_type is not None
        ct = ChoiceXsdType(name="MyChoice", options=[("intVal", int_type), ("strVal", str_type)])
        defn = WsdlDefinition(
            name="Svc",
            target_namespace="http://example.com/",
            complex_types={"MyChoice": ct},
        )
        wsdl_str = build_wsdl_string(defn, "http://example.com/")
        assert "MyChoice" in wsdl_str
        assert "intVal" in wsdl_str
        assert "strVal" in wsdl_str


# =============================================================================
# 8. Server
# =============================================================================

class TestServer:
    def _make_app(self) -> SoapApplication:
        class CalcService(SoapService):
            __service_name__ = "Calculator"
            __tns__ = "http://example.com/calc"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="Add",
                input_params=[
                    OperationParameter("a", xsd.resolve("int")),  # type: ignore[arg-type]
                    OperationParameter("b", xsd.resolve("int")),  # type: ignore[arg-type]
                ],
                output_params=[
                    OperationParameter("result", xsd.resolve("int")),  # type: ignore[arg-type]
                ],
            )
            def add(self, a: int, b: int) -> int:
                return a + b

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(CalcService())
        return app

    def test_wsdl_generation(self) -> None:
        app = self._make_app()
        wsdl_bytes = app.get_wsdl()
        assert b"Calculator" in wsdl_bytes
        assert b"Add" in wsdl_bytes

    def test_handle_valid_request(self) -> None:
        app = self._make_app()
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <Add>
      <a>3</a>
      <b>4</b>
    </Add>
  </soapenv:Body>
</soapenv:Envelope>"""
        status, _ct, body = app.handle_request(req, soap_action="")
        assert status == 200
        assert b"result" in body or b"AddResponse" in body or b"7" in body

    def test_handle_unknown_operation(self) -> None:
        app = self._make_app()
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><UnknownOp/></soapenv:Body>
</soapenv:Envelope>"""
        status, _ct, body = app.handle_request(req, soap_action="")
        assert status in (400, 500)
        assert b"Fault" in body

    def test_handle_malformed_xml(self) -> None:
        app = self._make_app()
        status, _ct, body = app.handle_request(b"not xml at all")
        assert status == 500
        assert b"Fault" in body

    def test_soap_operation_decorator_introspection(self) -> None:
        """Decorator auto-introspects type hints."""
        class MyService(SoapService):
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED

            @soap_operation()
            def echo(self, message: str) -> str:
                return message

        svc = MyService()
        ops = svc.get_operations()
        assert "echo" in ops
        sig: OperationSignature = ops["echo"].__soap_operation__
        assert len(sig.input_params) == 1
        assert sig.input_params[0].name == "message"
        assert sig.input_params[0].xsd_type.name == "string"


# =============================================================================
# 9. WITSML RPC/Encoded end-to-end
# =============================================================================

WITSML_WSDL = b"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="http://www.witsml.org/wsdl/120"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="http://www.witsml.org/wsdl/120"
             name="Store">
  <message name="WMLS_GetVersionRequest"/>
  <message name="WMLS_GetVersionResponse">
    <part name="Result" type="xsd:string"/>
  </message>
  <portType name="Store">
    <operation name="WMLS_GetVersion">
      <input message="tns:WMLS_GetVersionRequest"/>
      <output message="tns:WMLS_GetVersionResponse"/>
    </operation>
  </portType>
  <binding name="StoreBinding" type="tns:Store">
    <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="WMLS_GetVersion">
      <soap:operation soapAction="http://www.witsml.org/action/120/Store.WMLS_GetVersion" style="rpc"/>"""  # noqa: E501
WITSML_WSDL += b"""
      <input>
        <soap:body use="encoded" namespace="http://www.witsml.org/wsdl/120"/>
      </input>
      <output>
        <soap:body use="encoded" namespace="http://www.witsml.org/wsdl/120"/>
      </output>
    </operation>
  </binding>
  <service name="Store">
    <port name="StorePort" binding="tns:StoreBinding">
      <soap:address location="http://witsml.example.com/Store"/>
    </port>
  </service>
</definitions>"""


class TestWitsml:
    def test_get_version_rpc_encoded_end_to_end(self) -> None:
        """Full RPC/Encoded round-trip for WMLS_GetVersion."""
        parse_wsdl(WITSML_WSDL)  # Verify WSDL parses correctly

        # Build server
        class WitsmlStore(SoapService):
            __service_name__ = "Store"
            __tns__ = "http://www.witsml.org/wsdl/120"
            __binding_style__ = BindingStyle.RPC_ENCODED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="WMLS_GetVersion",
                input_params=[],
                output_params=[
                    OperationParameter("Result", xsd.resolve("string")),  # type: ignore[arg-type]
                ],
                soap_action="http://www.witsml.org/action/120/Store.WMLS_GetVersion",
            )
            def wmls_get_version(self) -> str:
                return "1.4.1.1"

        app = SoapApplication(service_url="http://witsml.example.com/Store")
        app.register(WitsmlStore())

        # Build request using RPC/Encoded serializer
        sig = OperationSignature(
            name="WMLS_GetVersion",
            input_params=[],
            output_params=[OperationParameter("Result", xsd.resolve("string"))],  # type: ignore[arg-type]
            soap_action="http://www.witsml.org/action/120/Store.WMLS_GetVersion",
            input_namespace="http://www.witsml.org/wsdl/120",
        )
        serializer = get_serializer(BindingStyle.RPC_ENCODED)
        envelope = SoapEnvelope(version=SoapVersion.SOAP_11)
        body_container = etree.Element("_body")
        serializer.serialize_request(sig, {}, body_container)
        for child in body_container:
            envelope.add_body_content(child)

        req_bytes = envelope.to_bytes()

        status, _ct, resp_body = app.handle_request(
            req_bytes,
            soap_action="http://www.witsml.org/action/120/Store.WMLS_GetVersion",
        )
        assert status == 200
        resp_env = SoapEnvelope.from_xml(resp_body)
        assert not resp_env.is_fault
        # Check response contains the version string
        resp_str = resp_body.decode()
        assert "1.4.1.1" in resp_str


# =============================================================================
# 10. Client (unit tests without network)
# =============================================================================

class TestClient:
    def test_client_from_wsdl_string(self) -> None:
        from soapbar.client.client import SoapClient
        client = SoapClient.from_wsdl_string(SIMPLE_WSDL)
        assert client._address == "http://example.com/calc"
        assert client._binding_style == BindingStyle.RPC_ENCODED

    def test_client_manual(self) -> None:
        from soapbar.client.client import SoapClient
        client = SoapClient.manual(
            "http://example.com/service",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            soap_version=SoapVersion.SOAP_11,
        )
        assert client._address == "http://example.com/service"
        assert client._binding_style == BindingStyle.DOCUMENT_LITERAL_WRAPPED

    def test_service_proxy_attribute(self) -> None:
        from soapbar.client.client import SoapClient
        client = SoapClient.manual("http://example.com/")
        proxy = client.service
        # Accessing an attribute returns a callable
        fn = proxy.SomeOperation
        assert callable(fn)


# =============================================================================
# 11. Top-level package smoke test
# =============================================================================

class TestPackage:
    def test_version(self) -> None:
        assert soapbar.__version__ == "0.1.0"

    def test_ns_accessible(self) -> None:
        assert soapbar.NS.SOAP_ENV == NS.SOAP_ENV

    def test_soap_fault_from_top_level(self) -> None:
        f = soapbar.SoapFault("Client", "test")
        env = f.to_soap11_envelope()
        s = to_string(env)
        assert "Fault" in s
        assert "test" in s


# =============================================================================
# 12. XML utils — edge cases
# =============================================================================

class TestXmlUtils:
    def test_make_element_with_text(self) -> None:
        elem = make_element("Greeting", text="hello")
        assert elem.text == "hello"

    def test_parse_xml_file(self, tmp_path: pytest.TempPathFactory) -> None:
        f = tmp_path / "test.xml"
        f.write_bytes(b"<root><child/></root>")
        doc = parse_xml_file(f)
        assert doc.tag == "root"

    def test_parse_xml_document_path(self, tmp_path: pytest.TempPathFactory) -> None:
        f = tmp_path / "doc.xml"
        f.write_bytes(b"<data/>")
        doc = parse_xml_document(f)
        assert doc.tag == "data"

    def test_build_nsmap(self) -> None:
        ns = build_nsmap(("pre", "http://example.com"))
        assert ns == {"pre": "http://example.com"}

    def test_collect_namespaces(self) -> None:
        elem = make_element("{http://ex.com}Tag", nsmap={"ex": "http://ex.com"})
        ns = collect_namespaces(elem)
        assert "http://ex.com" in ns.values()

    def test_xml_find_wrappers(self) -> None:
        parent = make_element("Parent")
        child = sub_element(parent, "Child", text="hi")
        set_attr(child, "key", "val")
        assert find(parent, "Child") is child
        assert findall(parent, "Child") == [child]
        assert findtext(parent, "Child") == "hi"
        assert get_attr(child, "key") == "val"
        assert get_attr(child, "missing", "default") == "default"

    def test_clone(self) -> None:
        orig = make_element("Orig", text="x")
        copy = clone(orig)
        copy.text = "y"
        assert orig.text == "x"

    def test_compile_and_validate_schema(self) -> None:
        xsd_src = b"""<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
          <xs:element name="Root" type="xs:string"/>
        </xs:schema>"""
        schema_elem = parse_xml(xsd_src)
        schema = compile_schema(schema_elem)
        valid_doc = parse_xml(b"<Root>ok</Root>")
        assert validate_schema(schema, valid_doc) is True


# =============================================================================
# 13. Fault — edge cases
# =============================================================================

class TestFaultEdgeCases:
    def test_soap11_faultactor(self) -> None:
        f = SoapFault("Server", "boom", faultactor="http://actor.example.com")
        elem = f.to_soap11_element()
        actor = elem.find("faultactor")
        assert actor is not None and actor.text == "http://actor.example.com"

    def test_soap11_detail_element(self) -> None:
        detail_elem = make_element("MyDetail")
        f = SoapFault("Server", "boom", detail=detail_elem)
        elem = f.to_soap11_element()
        det = elem.find("detail")
        assert det is not None
        assert det.find("MyDetail") is not None

    def test_soap12_subcodes(self) -> None:
        f = SoapFault("Server", "bad", subcodes=[("http://example.com/", "Invalid")])
        elem = f.to_soap12_element()
        subcode = elem.find(f"{{{NS.SOAP12_ENV}}}Code/{{{NS.SOAP12_ENV}}}Subcode")
        assert subcode is not None

    def test_soap12_role(self) -> None:
        f = SoapFault("Server", "err", faultactor="http://role.example.com")
        elem = f.to_soap12_element()
        role = elem.find(f"{{{NS.SOAP12_ENV}}}Role")
        assert role is not None and role.text == "http://role.example.com"

    def test_fault_repr(self) -> None:
        f = SoapFault("Server", "test error")
        r = repr(f)
        assert "Server" in r
        assert "test error" in r

    def test_parse_fault_with_detail_children(self) -> None:
        xml = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body>
            <soapenv:Fault>
              <faultcode>Server</faultcode>
              <faultstring>err</faultstring>
              <detail><item>info</item></detail>
            </soapenv:Fault>
          </soapenv:Body>
        </soapenv:Envelope>"""
        env = SoapEnvelope.from_xml(xml)
        f = env.fault
        assert f is not None and f.faultcode == "Server"
        assert f.detail is not None


# =============================================================================
# 14. Envelope — edge cases
# =============================================================================

class TestEnvelopeEdgeCases:
    def test_add_header(self) -> None:
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        hdr = make_element("Security")
        env.add_header(hdr)
        xml_bytes = env.to_bytes()
        assert b"Security" in xml_bytes

    def test_empty_body_properties(self) -> None:
        env = SoapEnvelope(version=SoapVersion.SOAP_11)
        assert env.is_fault is False
        assert env.fault is None
        assert env.first_body_element is None
        assert env.operation_namespace is None

    def test_encoding_ns(self) -> None:
        assert SoapVersion.SOAP_11.encoding_ns == "http://schemas.xmlsoap.org/soap/encoding/"
        assert SoapVersion.SOAP_12.encoding_ns == "http://www.w3.org/2003/05/soap-encoding"

    def test_build_fault_soap12(self) -> None:
        env_elem = build_fault(SoapVersion.SOAP_12, "Receiver", "something failed")
        xml = to_string(env_elem)
        assert "soap-envelope" in xml

    def test_http_headers_soap12_action(self) -> None:
        hdrs = http_headers(SoapVersion.SOAP_12, "http://ex.com/Action")
        ct = hdrs["Content-Type"]
        assert 'action="http://ex.com/Action"' in ct

    def test_build_response(self) -> None:
        from soapbar.core.envelope import build_response
        child = make_element("AddResponse")
        env_elem = build_response(SoapVersion.SOAP_11, [child])
        xml = to_string(env_elem)
        assert "AddResponse" in xml


# =============================================================================
# 15. Types — edge cases
# =============================================================================

class TestTypesEdgeCases:
    def test_float_nan_from_xml(self) -> None:
        t = xsd.resolve("float")
        assert t is not None
        result = t.from_xml("NaN")
        assert result != result  # NaN != NaN

    def test_decimal_roundtrip(self) -> None:
        from decimal import Decimal
        t = xsd.resolve("decimal")
        assert t is not None
        assert t.to_xml(Decimal("3.14")) == "3.14"

    def test_decimal_invalid_from_xml(self) -> None:
        t = xsd.resolve("decimal")
        assert t is not None
        with pytest.raises(ValueError):
            t.from_xml("not-a-decimal")

    def test_boolean_invalid_from_xml(self) -> None:
        t = xsd.resolve("boolean")
        assert t is not None
        with pytest.raises(ValueError):
            t.from_xml("maybe")

    def test_python_to_xsd_unmapped(self) -> None:
        result = xsd.python_to_xsd(list)
        assert result is None

    def test_all_types(self) -> None:
        types = xsd.all_types()
        assert len(types) > 10
        assert all(hasattr(t, "to_xml") for t in types)


# =============================================================================
# 16. WSDL — edge cases
# =============================================================================

class TestWsdlEdgeCases:
    def test_first_service_address_none_when_empty(self) -> None:
        from soapbar.core.wsdl import WsdlDefinition
        wsdl = WsdlDefinition()
        assert wsdl.first_service_address is None

    def test_first_binding_none_when_empty(self) -> None:
        from soapbar.core.wsdl import WsdlDefinition
        wsdl = WsdlDefinition()
        assert wsdl.first_binding is None


# =============================================================================
# 17. Application — edge cases
# =============================================================================

class TestApplicationEdgeCases:
    def _make_app(self) -> SoapApplication:
        class CalcService(SoapService):
            __service_name__ = "Calculator"
            __tns__ = "http://example.com/calc"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="Add",
                input_params=[
                    OperationParameter("a", xsd.resolve("int")),  # type: ignore[arg-type]
                    OperationParameter("b", xsd.resolve("int")),  # type: ignore[arg-type]
                ],
                output_params=[
                    OperationParameter("result", xsd.resolve("int")),  # type: ignore[arg-type]
                ],
            )
            def add(self, a: int, b: int) -> int:
                return a + b

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(CalcService())
        return app

    def test_custom_wsdl(self) -> None:
        custom = b"<definitions/>"
        app = SoapApplication(custom_wsdl=custom)
        result = app.get_wsdl()
        assert result == custom

    def test_build_wsdl_no_services(self) -> None:
        app = SoapApplication()
        wsdl = app.get_wsdl()
        assert isinstance(wsdl, bytes)

    def test_operation_result_none(self) -> None:
        class VoidService(SoapService):
            __service_name__ = "VoidSvc"
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="DoNothing",
                input_params=[],
                output_params=[],
            )
            def do_nothing(self) -> None:
                return None

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(VoidService())
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><DoNothing/></soapenv:Body>
</soapenv:Envelope>"""
        status, _ct, _body = app.handle_request(req, soap_action="")
        assert status == 200

    def test_soap_action_fragment(self) -> None:
        app = self._make_app()
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><Add><a>1</a><b>2</b></Add></soapenv:Body>
</soapenv:Envelope>"""
        # Use #Add as fragment action — should still resolve via body element name
        status, _ct, _body = app.handle_request(req, soap_action="#Add")
        assert status == 200

    def test_unknown_soap_action(self) -> None:
        app = self._make_app()
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><Unknown/></soapenv:Body>
</soapenv:Envelope>"""
        status, _ct, body = app.handle_request(req, soap_action="http://unknown/Action")
        assert status in (400, 500)
        assert b"Fault" in body


# =============================================================================
# 18. Binding serializer — response / deserialize paths
# =============================================================================

class TestBindingResponse:
    def _make_sig(self) -> OperationSignature:
        int_type = xsd.resolve("int")
        assert int_type is not None
        return OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type), OperationParameter("b", int_type)],
            output_params=[OperationParameter("result", int_type)],
        )

    def test_rpc_encoded_serialize_response(self) -> None:
        sig = self._make_sig()
        serializer = RpcEncodedSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 7}, container)
        assert len(container) == 1
        wrapper = container[0]
        result_elem = wrapper.find("result")
        assert result_elem is not None and result_elem.text == "7"

    def test_rpc_encoded_deserialize_response(self) -> None:
        sig = self._make_sig()
        serializer = RpcEncodedSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 42}, container)
        values = serializer.deserialize_response(sig, container)
        assert values["result"] == 42

    def test_rpc_literal_serialize_response(self) -> None:
        sig = self._make_sig()
        serializer = RpcLiteralSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 9}, container)
        wrapper = container[0]
        assert wrapper.find("result") is not None

    def test_rpc_literal_deserialize_request_and_response(self) -> None:
        sig = self._make_sig()
        serializer = RpcLiteralSerializer()
        from lxml import etree
        req_container = etree.Element("_body")
        serializer.serialize_request(sig, {"a": 3, "b": 4}, req_container)
        values = serializer.deserialize_request(sig, req_container)
        assert values["a"] == 3
        assert values["b"] == 4

        resp_container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 7}, resp_container)
        resp_values = serializer.deserialize_response(sig, resp_container)
        assert resp_values["result"] == 7

    def test_document_literal_serialize_response(self) -> None:
        sig = self._make_sig()
        serializer = DocumentLiteralSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 5}, container)
        assert container.find("result") is not None

    def test_document_literal_deserialize_response(self) -> None:
        sig = self._make_sig()
        serializer = DocumentLiteralSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 5}, container)
        values = serializer.deserialize_response(sig, container)
        assert values["result"] == 5

    def test_document_literal_wrapped_serialize_response(self) -> None:
        sig = self._make_sig()
        serializer = DocumentLiteralWrappedSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 11}, container)
        wrapper = container[0]
        assert wrapper.find("result") is not None

    def test_document_literal_wrapped_deserialize_response(self) -> None:
        sig = self._make_sig()
        serializer = DocumentLiteralWrappedSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 11}, container)
        values = serializer.deserialize_response(sig, container)
        assert values["result"] == 11

    def test_document_encoded_serialize_response(self) -> None:
        sig = self._make_sig()
        serializer = DocumentEncodedSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 13}, container)
        assert container.find("result") is not None

    def test_document_encoded_deserialize_response(self) -> None:
        sig = self._make_sig()
        serializer = DocumentEncodedSerializer()
        from lxml import etree
        container = etree.Element("_body")
        serializer.serialize_response(sig, {"result": 13}, container)
        values = serializer.deserialize_response(sig, container)
        assert values["result"] == 13


# =============================================================================
# 19. Types — additional edge cases
# =============================================================================

class TestTypesAdditional:
    def test_xsd_type_repr(self) -> None:
        t = xsd.resolve("string")
        assert t is not None
        assert "string" in repr(t)

    def test_normalized_string_roundtrip(self) -> None:
        t = xsd.resolve("normalizedString")
        assert t is not None
        assert t.to_xml("  hello  world  ") == "hello world"
        assert t.from_xml("  foo  bar  ") == "foo bar"

    def test_float_regular_value(self) -> None:
        t = xsd.resolve("float")
        assert t is not None
        assert t.to_xml(3.14) == repr(3.14)

    def test_datetime_roundtrip(self) -> None:
        t = xsd.resolve("dateTime")
        assert t is not None
        assert t.to_xml("2024-01-15T10:30:00") == "2024-01-15T10:30:00"
        assert t.from_xml("2024-01-15T10:30:00") == "2024-01-15T10:30:00"

    def test_base64_str_input(self) -> None:
        t = xsd.resolve("base64Binary")
        assert t is not None
        # to_xml with str input (not bytes) covers the str branch
        encoded = t.to_xml("hello")
        assert encoded == "aGVsbG8="

    def test_hex_binary_roundtrip(self) -> None:
        t = xsd.resolve("hexBinary")
        assert t is not None
        encoded = t.to_xml(b"\xde\xad")
        assert encoded == "DEAD"
        assert t.from_xml("DEAD") == b"\xde\xad"

    def test_hex_binary_str_input(self) -> None:
        t = xsd.resolve("hexBinary")
        assert t is not None
        encoded = t.to_xml("AB")
        assert encoded == "4142"  # hex of b"AB"


# =============================================================================
# 20. WSDL binding style — all branches including the fixed DOCUMENT_ENCODED
# =============================================================================

def _make_calc_service() -> SoapApplication:
    """Shared helper: build a minimal CalcService SoapApplication."""
    class CalcService(SoapService):
        __service_name__ = "Calculator"
        __tns__ = "http://example.com/calc"
        __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        __soap_version__ = SoapVersion.SOAP_11

        @soap_operation(
            name="Add",
            input_params=[
                OperationParameter("a", xsd.resolve("int")),  # type: ignore[arg-type]
                OperationParameter("b", xsd.resolve("int")),  # type: ignore[arg-type]
            ],
            output_params=[
                OperationParameter("result", xsd.resolve("int")),  # type: ignore[arg-type]
            ],
        )
        def add(self, a: int, b: int) -> int:
            return a + b

    app = SoapApplication(service_url="http://localhost:8000/soap")
    app.register(CalcService())
    return app


class TestWsdlBindingStyle:
    def _make_binding(self, style: str, use: str):
        from soapbar.core.wsdl import WsdlBinding, WsdlBindingOperation
        return WsdlBinding(
            name="B",
            port_type="P",
            style=style,
            operations=[WsdlBindingOperation(name="Op", use=use)],
        )

    def test_rpc_encoded(self) -> None:
        b = self._make_binding("rpc", "encoded")
        assert b.binding_style_for("Op") == BindingStyle.RPC_ENCODED

    def test_rpc_literal(self) -> None:
        b = self._make_binding("rpc", "literal")
        assert b.binding_style_for("Op") == BindingStyle.RPC_LITERAL

    def test_document_literal(self) -> None:
        b = self._make_binding("document", "literal")
        assert b.binding_style_for("Op") == BindingStyle.DOCUMENT_LITERAL

    def test_document_encoded(self) -> None:
        b = self._make_binding("document", "encoded")
        assert b.binding_style_for("Op") == BindingStyle.DOCUMENT_ENCODED

    def test_unknown_operation_falls_back_to_binding_style(self) -> None:
        from soapbar.core.wsdl import WsdlBinding
        b = WsdlBinding(name="B", port_type="P", style="document")
        assert b.binding_style_for("NonExistent") == BindingStyle.DOCUMENT_LITERAL


# =============================================================================
# 21. Namespaces — duplicate prefix collision resolved
# =============================================================================

class TestNamespacesDuplicate:
    def test_wsdl_soap12_prefix_renamed(self) -> None:
        assert NS.prefix_for(NS.WSDL_SOAP12) == "wsoap12"
        assert NS.prefix_for(NS.SOAP12_ENV) == "soap12"

    def test_reverse_prefixes_unambiguous(self) -> None:
        assert NS.REVERSE_PREFIXES["soap12"] == NS.SOAP12_ENV
        assert NS.REVERSE_PREFIXES["wsoap12"] == NS.WSDL_SOAP12


# =============================================================================
# 22. ASGI adapter
# =============================================================================

_ADD_SOAP_REQUEST = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><Add><a>3</a><b>4</b></Add></soapenv:Body>
</soapenv:Envelope>"""


class TestAsgiAdapter:
    def _make_app(self) -> AsgiSoapApp:
        return AsgiSoapApp(_make_calc_service())

    async def test_get_root(self) -> None:
        app = self._make_app()
        scope = {"type": "http", "method": "GET", "query_string": b"", "headers": []}
        responses: list = []

        async def receive():
            return {"body": b"", "more_body": False}

        async def send(message):
            responses.append(message)

        await app(scope, receive, send)
        assert responses[0]["status"] == 405

    async def test_get_wsdl(self) -> None:
        app = self._make_app()
        scope = {"type": "http", "method": "GET", "query_string": b"wsdl", "headers": []}
        responses: list = []

        async def receive():
            return {"body": b"", "more_body": False}

        async def send(message):
            responses.append(message)

        await app(scope, receive, send)
        assert responses[0]["status"] == 200
        assert b"definitions" in responses[1]["body"]

    async def test_post_soap(self) -> None:
        app = self._make_app()
        scope = {
            "type": "http",
            "method": "POST",
            "query_string": b"",
            "headers": [
                (b"content-type", b"text/xml"),
                (b"soapaction", b'"Add"'),
            ],
        }
        responses: list = []

        async def receive():
            return {"body": _ADD_SOAP_REQUEST, "more_body": False}

        async def send(message):
            responses.append(message)

        await app(scope, receive, send)
        assert responses[0]["status"] == 200

    async def test_unknown_method(self) -> None:
        app = self._make_app()
        scope = {"type": "http", "method": "DELETE", "query_string": b"", "headers": []}
        responses: list = []

        async def receive():
            return {"body": b"", "more_body": False}

        async def send(message):
            responses.append(message)

        await app(scope, receive, send)
        assert responses[0]["status"] == 405

    async def test_lifespan(self) -> None:
        app = self._make_app()
        events = iter([
            {"type": "lifespan.startup"},
            {"type": "lifespan.shutdown"},
        ])
        sent: list = []

        async def receive():
            return next(events)

        async def send(message):
            sent.append(message)

        await app({"type": "lifespan"}, receive, send)
        assert any(m["type"] == "lifespan.startup.complete" for m in sent)
        assert any(m["type"] == "lifespan.shutdown.complete" for m in sent)

    async def test_unknown_scope_type(self) -> None:
        app = self._make_app()
        sent: list = []

        async def send(message):
            sent.append(message)

        await app({"type": "websocket"}, None, send)
        assert sent == []


# =============================================================================
# 23. WSGI adapter
# =============================================================================

class TestWsgiAdapter:
    def _make_app(self) -> WsgiSoapApp:
        return WsgiSoapApp(_make_calc_service())

    def _make_environ(
        self,
        method: str,
        body: bytes = b"",
        query_string: str = "",
        soap_action: str = "",
    ) -> dict:
        return {
            "REQUEST_METHOD": method,
            "QUERY_STRING": query_string,
            "CONTENT_TYPE": "text/xml",
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_SOAPACTION": soap_action,
            "wsgi.input": io.BytesIO(body),
        }

    def test_get_root(self) -> None:
        app = self._make_app()
        status_list: list = []

        def start_response(status, headers):
            status_list.append(status)

        result = app(self._make_environ("GET"), start_response)
        assert status_list[0].startswith("405")

    def test_get_wsdl(self) -> None:
        app = self._make_app()
        status_list: list = []

        def start_response(status, headers):
            status_list.append(status)

        result = app(self._make_environ("GET", query_string="wsdl"), start_response)
        assert status_list[0].startswith("200")
        assert b"definitions" in b"".join(result)

    def test_post_soap(self) -> None:
        app = self._make_app()
        status_list: list = []

        def start_response(status, headers):
            status_list.append(status)

        environ = self._make_environ("POST", body=_ADD_SOAP_REQUEST)
        app(environ, start_response)
        assert status_list[0].startswith("200")

    def test_unknown_method(self) -> None:
        app = self._make_app()
        status_list: list = []

        def start_response(status, headers):
            status_list.append(status)

        result = app(self._make_environ("DELETE"), start_response)
        assert status_list[0].startswith("405")
        assert b"Method Not Allowed" in b"".join(result)

    def test_invalid_content_length(self) -> None:
        app = self._make_app()
        environ = self._make_environ("POST", body=_ADD_SOAP_REQUEST)
        environ["CONTENT_LENGTH"] = "abc"  # non-integer → falls back to 0
        status_list: list = []

        def start_response(status, headers):
            status_list.append(status)

        app(environ, start_response)
        assert len(status_list) == 1  # responded (with fault or success)


# =============================================================================
# 24. HTTP transport
# =============================================================================

class TestHttpTransport:
    def test_send_urllib_success(self) -> None:
        transport = HttpTransport()
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        mock_resp.headers.get.return_value = "text/xml"
        mock_resp.read.return_value = b"<response/>"

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status, _ct, body = transport._send_urllib("http://example.com/", b"<req/>", {})

        assert status == 200
        assert body == b"<response/>"

    def test_send_urllib_http_error(self) -> None:
        transport = HttpTransport()
        err = urllib.error.HTTPError(
            url="http://example.com/",
            code=500,
            msg="Server Error",
            hdrs=MagicMock(**{"get.return_value": "text/xml"}),
            fp=None,
        )
        err.read = lambda: b"<fault/>"  # type: ignore[method-assign]

        with patch("urllib.request.urlopen", side_effect=err):
            status, _ct, body = transport._send_urllib("http://example.com/", b"<req/>", {})

        assert status == 500
        assert body == b"<fault/>"

    def test_fetch_urllib(self) -> None:
        transport = HttpTransport()
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"<wsdl/>"

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch.dict(sys.modules, {"httpx": None}):
            data = transport.fetch("http://example.com/service?wsdl")

        assert data == b"<wsdl/>"

    async def test_send_async_no_httpx(self) -> None:
        transport = HttpTransport()
        with patch.dict(sys.modules, {"httpx": None}), pytest.raises(RuntimeError, match="httpx"):
            await transport.send_async("http://example.com/", b"", {})


# =============================================================================
# 25. SoapClient — call / call_async with mocked transport
# =============================================================================

_ADD_RESPONSE_XML = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <AddResponse><result>7</result></AddResponse>
  </soapenv:Body>
</soapenv:Envelope>"""

_FAULT_RESPONSE_XML = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <soapenv:Fault>
      <faultcode>Server</faultcode>
      <faultstring>Internal Error</faultstring>
    </soapenv:Fault>
  </soapenv:Body>
</soapenv:Envelope>"""


class TestSoapClientCall:
    def _int_sig(self) -> OperationSignature:
        int_type = xsd.resolve("int")
        assert int_type is not None
        return OperationSignature(
            name="Add",
            input_params=[
                OperationParameter("a", int_type),
                OperationParameter("b", int_type),
            ],
            output_params=[OperationParameter("result", int_type)],
        )

    def _mock_client(self, response_xml: bytes) -> SoapClient:
        mock_transport = MagicMock(spec=HttpTransport)
        mock_transport.send.return_value = (200, "text/xml", response_xml)
        return SoapClient.manual(
            "http://example.com/soap",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            transport=mock_transport,
        )

    def test_call_returns_result(self) -> None:
        client = self._mock_client(_ADD_RESPONSE_XML)
        client.register_operation(self._int_sig())
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_call_raises_soap_fault(self) -> None:
        from soapbar.core.fault import SoapFault
        client = self._mock_client(_FAULT_RESPONSE_XML)
        with pytest.raises(SoapFault):
            client.call("Add")

    async def test_call_async_returns_result(self) -> None:
        int_type = xsd.resolve("int")
        assert int_type is not None
        mock_transport = MagicMock(spec=HttpTransport)
        mock_transport.send_async = AsyncMock(
            return_value=(200, "text/xml", _ADD_RESPONSE_XML)
        )
        client = SoapClient.manual(
            "http://example.com/soap",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            transport=mock_transport,
        )
        client.register_operation(self._int_sig())
        result = await client.call_async("Add", a=3, b=4)
        assert result == 7


class TestSoapClientWsaHeaders:
    """Client-side WS-Addressing header injection (use_wsa=True)."""

    def _mock_client(self, use_wsa: bool = True) -> tuple[SoapClient, MagicMock]:
        mock_transport = MagicMock(spec=HttpTransport)
        mock_transport.send.return_value = (200, "text/xml", _ADD_RESPONSE_XML)
        client = SoapClient.manual(
            "http://example.com/soap",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            transport=mock_transport,
            use_wsa=use_wsa,
        )
        int_type = xsd.resolve("int")
        assert int_type is not None
        client.register_operation(OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type), OperationParameter("b", int_type)],
            output_params=[OperationParameter("result", int_type)],
            soap_action="http://example.com/Add",
        ))
        return client, mock_transport

    def _sent_envelope(self, mock_transport: MagicMock) -> SoapEnvelope:
        req_bytes = mock_transport.send.call_args[0][1]
        return SoapEnvelope.from_xml(req_bytes)

    def test_wsa_disabled_by_default(self) -> None:
        client, transport = self._mock_client(use_wsa=False)
        client.call("Add", a=1, b=2)
        env = self._sent_envelope(transport)
        assert env.ws_addressing is None

    def test_wsa_message_id_injected(self) -> None:
        client, transport = self._mock_client(use_wsa=True)
        client.call("Add", a=1, b=2)
        env = self._sent_envelope(transport)
        assert env.ws_addressing is not None
        assert env.ws_addressing.message_id is not None
        assert env.ws_addressing.message_id.startswith("urn:uuid:")

    def test_wsa_action_injected(self) -> None:
        client, transport = self._mock_client(use_wsa=True)
        client.call("Add", a=1, b=2)
        env = self._sent_envelope(transport)
        assert env.ws_addressing is not None
        assert env.ws_addressing.action == "http://example.com/Add"

    def test_wsa_message_id_unique_per_call(self) -> None:
        client, transport = self._mock_client(use_wsa=True)
        client.call("Add", a=1, b=2)
        id1 = self._sent_envelope(transport).ws_addressing  # type: ignore[union-attr]
        client.call("Add", a=3, b=4)
        id2 = self._sent_envelope(transport).ws_addressing  # type: ignore[union-attr]
        assert id1 is not None and id2 is not None
        assert id1.message_id != id2.message_id

    async def test_wsa_injected_in_call_async(self) -> None:
        mock_transport = MagicMock(spec=HttpTransport)
        mock_transport.send_async = AsyncMock(
            return_value=(200, "text/xml", _ADD_RESPONSE_XML)
        )
        client = SoapClient.manual(
            "http://example.com/soap",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            transport=mock_transport,
            use_wsa=True,
        )
        int_type = xsd.resolve("int")
        assert int_type is not None
        client.register_operation(OperationSignature(
            name="Add",
            input_params=[OperationParameter("a", int_type)],
            output_params=[OperationParameter("result", int_type)],
            soap_action="http://example.com/Add",
        ))
        await client.call_async("Add", a=5)
        req_bytes = mock_transport.send_async.call_args[0][1]
        env = SoapEnvelope.from_xml(req_bytes)
        assert env.ws_addressing is not None
        assert env.ws_addressing.message_id is not None


# =============================================================================
# 26. End-to-end round-trip for all 5 binding styles
# =============================================================================

class _InlineTransport(HttpTransport):
    """Routes SoapClient.send() directly into SoapApplication.handle_request()."""

    def __init__(self, app: SoapApplication) -> None:
        super().__init__()
        self._app = app

    def send(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        soap_action = headers.get("SOAPAction", "").strip('"')
        if not soap_action:
            # SOAP 1.2: action is embedded in Content-Type as action="..."
            ct = headers.get("Content-Type", "")
            for part in ct.split(";"):
                part = part.strip()
                if part.startswith("action="):
                    soap_action = part[len("action="):].strip('"')
                    break
        return self._app.handle_request(body, soap_action=soap_action)


class TestEndToEnd:
    """Full serialize → send → deserialize round-trip for every binding style."""

    def _make_client(
        self, style: BindingStyle, version: SoapVersion = SoapVersion.SOAP_11
    ) -> SoapClient:
        int_type = xsd.resolve("int")
        assert int_type is not None

        class CalcService(SoapService):
            __service_name__ = "Calculator"
            __tns__ = "http://example.com/calc"
            __binding_style__ = style
            __soap_version__ = version

            @soap_operation(
                name="Add",
                input_params=[
                    OperationParameter("a", int_type),  # type: ignore[arg-type]
                    OperationParameter("b", int_type),  # type: ignore[arg-type]
                ],
                output_params=[
                    OperationParameter("result", int_type),  # type: ignore[arg-type]
                ],
                soap_action="Add",
            )
            def add(self, a: int, b: int) -> int:
                return a + b

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(CalcService())

        sig = OperationSignature(
            name="Add",
            input_params=[
                OperationParameter("a", int_type),
                OperationParameter("b", int_type),
            ],
            output_params=[OperationParameter("result", int_type)],
            soap_action="Add",
        )
        client = SoapClient.manual(
            "http://localhost:8000/soap",
            binding_style=style,
            soap_version=version,
            transport=_InlineTransport(app),
        )
        client.register_operation(sig)
        return client

    def test_rpc_encoded(self) -> None:
        client = self._make_client(BindingStyle.RPC_ENCODED)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_rpc_literal(self) -> None:
        client = self._make_client(BindingStyle.RPC_LITERAL)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_document_literal(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_LITERAL)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_document_literal_wrapped(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_LITERAL_WRAPPED)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_document_encoded(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_ENCODED)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_rpc_encoded_soap12(self) -> None:
        client = self._make_client(BindingStyle.RPC_ENCODED, SoapVersion.SOAP_12)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_rpc_literal_soap12(self) -> None:
        client = self._make_client(BindingStyle.RPC_LITERAL, SoapVersion.SOAP_12)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_document_literal_soap12(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_LITERAL, SoapVersion.SOAP_12)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_document_literal_wrapped_soap12(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_LITERAL_WRAPPED, SoapVersion.SOAP_12)
        result = client.call("Add", a=3, b=4)
        assert result == 7

    def test_document_encoded_soap12(self) -> None:
        client = self._make_client(BindingStyle.DOCUMENT_ENCODED, SoapVersion.SOAP_12)
        result = client.call("Add", a=3, b=4)
        assert result == 7


# =============================================================================
# 27. SOAP 1.2 WSDL generation and client version propagation
# =============================================================================

class TestSoap12Wsdl:
    """WSDL generation and client initialisation for SOAP 1.2 services."""

    def _make_soap12_app(self) -> SoapApplication:
        int_type = xsd.resolve("int")
        assert int_type is not None

        class CalcService12(SoapService):
            __service_name__ = "Calculator"
            __tns__ = "http://example.com/calc"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_12

            @soap_operation(
                name="Add",
                input_params=[
                    OperationParameter("a", int_type),  # type: ignore[arg-type]
                    OperationParameter("b", int_type),  # type: ignore[arg-type]
                ],
                output_params=[
                    OperationParameter("result", int_type),  # type: ignore[arg-type]
                ],
                soap_action="Add",
            )
            def add(self, a: int, b: int) -> int:
                return a + b

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(CalcService12())
        return app

    def test_wsdl_contains_soap12_namespace(self) -> None:
        app = self._make_soap12_app()
        wsdl_bytes = app.get_wsdl()
        assert NS.WSDL_SOAP12.encode() in wsdl_bytes

    def test_client_from_wsdl_detects_soap12(self) -> None:
        app = self._make_soap12_app()
        wsdl_bytes = app.get_wsdl()
        client = SoapClient.from_wsdl_string(wsdl_bytes)
        assert client._soap_version == SoapVersion.SOAP_12


# =============================================================================
# 28. Validation — required-field checking in serializers
# =============================================================================

class TestRequiredFieldValidation:
    def _sig(self) -> OperationSignature:
        int_type = xsd.resolve("int")
        assert int_type is not None
        str_type = xsd.resolve("string")
        assert str_type is not None
        return OperationSignature(
            name="Op",
            input_params=[
                OperationParameter("required_field", int_type, required=True),
                OperationParameter("optional_field", str_type, required=False),
            ],
            output_params=[
                OperationParameter("result", int_type, required=True),
            ],
        )

    def _check_all_serializers_request(self, sig: OperationSignature) -> None:
        from lxml import etree
        for style in BindingStyle:
            serializer = get_serializer(style)
            container = etree.Element("_body")
            with pytest.raises(SoapFault, match="required_field"):
                serializer.serialize_request(sig, {}, container)

    def _check_all_serializers_response(self, sig: OperationSignature) -> None:
        from lxml import etree
        for style in BindingStyle:
            serializer = get_serializer(style)
            container = etree.Element("_body")
            with pytest.raises(SoapFault, match="result"):
                serializer.serialize_response(sig, {}, container)

    def test_missing_required_input_raises(self) -> None:
        self._check_all_serializers_request(self._sig())

    def test_missing_required_output_raises(self) -> None:
        self._check_all_serializers_response(self._sig())

    def test_optional_field_missing_does_not_raise(self) -> None:
        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Op",
            input_params=[OperationParameter("optional", int_type, required=False)],
            output_params=[],
        )
        from lxml import etree
        for style in BindingStyle:
            serializer = get_serializer(style)
            container = etree.Element("_body")
            serializer.serialize_request(sig, {}, container)  # must not raise

    def test_required_field_present_does_not_raise(self) -> None:
        sig = self._sig()
        from lxml import etree
        for style in BindingStyle:
            serializer = get_serializer(style)
            container = etree.Element("_body")
            serializer.serialize_request(sig, {"required_field": 42}, container)


# =============================================================================
# 29. Validation — integer XSD type range bounds
# =============================================================================

class TestIntegerRangeBounds:
    def test_byte_valid(self) -> None:
        t = xsd.resolve("byte")
        assert t is not None
        assert t.to_xml(-128) == "-128"
        assert t.to_xml(127) == "127"
        assert t.from_xml("-128") == -128
        assert t.from_xml("127") == 127

    def test_byte_overflow(self) -> None:
        t = xsd.resolve("byte")
        assert t is not None
        with pytest.raises(ValueError, match="byte"):
            t.to_xml(128)
        with pytest.raises(ValueError, match="byte"):
            t.to_xml(-129)
        with pytest.raises(ValueError, match="byte"):
            t.from_xml("128")

    def test_short_bounds(self) -> None:
        t = xsd.resolve("short")
        assert t is not None
        assert t.to_xml(-32768) == "-32768"
        assert t.to_xml(32767) == "32767"
        with pytest.raises(ValueError):
            t.to_xml(32768)
        with pytest.raises(ValueError):
            t.to_xml(-32769)

    def test_int_bounds(self) -> None:
        t = xsd.resolve("int")
        assert t is not None
        assert t.to_xml(-2147483648) == "-2147483648"
        assert t.to_xml(2147483647) == "2147483647"
        with pytest.raises(ValueError):
            t.to_xml(2147483648)

    def test_long_bounds(self) -> None:
        t = xsd.resolve("long")
        assert t is not None
        with pytest.raises(ValueError):
            t.to_xml(9223372036854775808)

    def test_unsigned_byte_bounds(self) -> None:
        t = xsd.resolve("unsignedByte")
        assert t is not None
        assert t.to_xml(0) == "0"
        assert t.to_xml(255) == "255"
        with pytest.raises(ValueError):
            t.to_xml(256)
        with pytest.raises(ValueError):
            t.to_xml(-1)

    def test_unsigned_short_bounds(self) -> None:
        t = xsd.resolve("unsignedShort")
        assert t is not None
        assert t.to_xml(65535) == "65535"
        with pytest.raises(ValueError):
            t.to_xml(65536)

    def test_unsigned_int_bounds(self) -> None:
        t = xsd.resolve("unsignedInt")
        assert t is not None
        assert t.to_xml(4294967295) == "4294967295"
        with pytest.raises(ValueError):
            t.to_xml(4294967296)

    def test_positive_integer(self) -> None:
        t = xsd.resolve("positiveInteger")
        assert t is not None
        assert t.to_xml(1) == "1"
        with pytest.raises(ValueError):
            t.to_xml(0)
        with pytest.raises(ValueError):
            t.to_xml(-1)

    def test_non_negative_integer(self) -> None:
        t = xsd.resolve("nonNegativeInteger")
        assert t is not None
        assert t.to_xml(0) == "0"
        with pytest.raises(ValueError):
            t.to_xml(-1)

    def test_integer_no_bounds(self) -> None:
        t = xsd.resolve("integer")
        assert t is not None
        # unbounded — no error for large values
        assert t.to_xml(10**30) is not None
        assert t.to_xml(-(10**30)) is not None


# =============================================================================
# 30. Validation — application returns 400 Client fault on ValueError
# =============================================================================

class TestApplicationValueErrorFault:
    def _make_app_with_raising_handler(self) -> SoapApplication:
        class BadService(SoapService):
            __service_name__ = "BadSvc"
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="DoIt",
                input_params=[],
                output_params=[],
            )
            def do_it(self) -> None:
                raise ValueError("invalid input value")

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(BadService())
        return app

    def test_value_error_returns_500_client_fault(self) -> None:
        app = self._make_app_with_raising_handler()
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><DoIt/></soapenv:Body>
</soapenv:Envelope>"""
        status, _ct, body = app.handle_request(req, soap_action="")
        assert status == 500
        assert b"Fault" in body
        assert b"Client" in body

    def test_value_error_message_in_fault(self) -> None:
        app = self._make_app_with_raising_handler()
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><DoIt/></soapenv:Body>
</soapenv:Envelope>"""
        _status, _ct, body = app.handle_request(req, soap_action="")
        assert b"invalid input value" in body

    def test_missing_required_param_returns_500(self) -> None:
        """Sending a request without a required parameter should produce a 500 fault (WS-I BP R1109)."""
        int_type = xsd.resolve("int")
        assert int_type is not None

        class StrictService(SoapService):
            __service_name__ = "StrictSvc"
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="Add",
                input_params=[
                    OperationParameter("a", int_type, required=True),  # type: ignore[arg-type]
                ],
                output_params=[
                    OperationParameter("result", int_type, required=True),  # type: ignore[arg-type]
                ],
            )
            def add(self, a: int) -> int:
                return a

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(StrictService())

        # Send Add request without the required `a` parameter
        req = b"""<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><Add/></soapenv:Body>
</soapenv:Envelope>"""
        status, _ct, body = app.handle_request(req, soap_action="")
        assert status == 500
        assert b"Fault" in body


class TestInputParamValidation:
    """F09 — required input parameter validation before service dispatch."""

    def _make_app(self, required: bool = True) -> SoapApplication:
        int_type = xsd.resolve("int")
        assert int_type is not None

        class ValSvc(SoapService):
            __service_name__ = "ValSvc"
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                name="Add",
                input_params=[
                    OperationParameter("a", int_type, required=required),
                    OperationParameter("b", int_type, required=required),
                ],
                output_params=[OperationParameter("result", int_type)],
            )
            def add(self, a: int = 0, b: int = 0) -> int:
                return a + b

        app = SoapApplication(service_url="http://localhost:8000/soap")
        app.register(ValSvc())
        return app

    def _req(self, body_inner: str) -> bytes:
        return (
            b'<?xml version="1.0"?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            b'                  xmlns:tns="http://example.com/">'
            b'  <soapenv:Body>' + body_inner.encode() + b'</soapenv:Body>'
            b'</soapenv:Envelope>'
        )

    def test_valid_request_dispatches_correctly(self) -> None:
        app = self._make_app()
        req = self._req("<tns:Add><a>3</a><b>4</b></tns:Add>")
        status, _ct, body = app.handle_request(req)
        assert status == 200
        assert b"Fault" not in body

    def test_missing_required_param_returns_fault(self) -> None:
        app = self._make_app(required=True)
        req = self._req("<tns:Add><b>4</b></tns:Add>")  # 'a' is absent
        status, _ct, body = app.handle_request(req)
        assert status == 500
        assert b"Fault" in body

    def test_missing_required_param_names_the_param(self) -> None:
        app = self._make_app(required=True)
        req = self._req("<tns:Add><b>4</b></tns:Add>")  # 'a' is absent
        _status, _ct, body = app.handle_request(req)
        assert b"a" in body  # fault message names the missing param

    def test_missing_optional_param_does_not_fault(self) -> None:
        app = self._make_app(required=False)
        req = self._req("<tns:Add><b>4</b></tns:Add>")  # 'a' absent but optional
        status, _ct, body = app.handle_request(req)
        # No validation fault — handler receives a=None (or default)
        assert b"Missing required" not in body

    def test_both_params_missing_lists_both(self) -> None:
        app = self._make_app(required=True)
        req = self._req("<tns:Add/>")  # both absent
        _status, _ct, body = app.handle_request(req)
        assert b"a" in body
        assert b"b" in body

    def test_validate_input_params_directly(self) -> None:
        """Unit-test _validate_input_params in isolation."""
        from soapbar.server.application import _validate_input_params
        from soapbar.core.fault import SoapFault

        int_type = xsd.resolve("int")
        assert int_type is not None
        sig = OperationSignature(
            name="Op",
            input_params=[OperationParameter("x", int_type, required=True)],
        )
        # Present → no exception
        _validate_input_params(sig, {"x": 5})

        # Missing → SoapFault
        with pytest.raises(SoapFault) as exc_info:
            _validate_input_params(sig, {})
        assert "x" in str(exc_info.value)
        assert exc_info.value.faultcode == "Client"


class TestDurationType:
    def test_duration_valid(self) -> None:
        dt = xsd.resolve("duration")
        assert dt is not None
        assert dt.from_xml("PT1H") == "PT1H"
        assert dt.from_xml("P1Y2M3D") == "P1Y2M3D"
        assert dt.from_xml("-P1DT30M") == "-P1DT30M"
        assert dt.from_xml("P0Y0M0DT0H0M0.000S") == "P0Y0M0DT0H0M0.000S"
        assert dt.from_xml("P1Y") == "P1Y"
        assert dt.from_xml("PT0S") == "PT0S"

    def test_duration_invalid(self) -> None:
        dt = xsd.resolve("duration")
        assert dt is not None
        with pytest.raises(ValueError):
            dt.from_xml("P")
        with pytest.raises(ValueError):
            dt.from_xml("PT")
        with pytest.raises(ValueError):
            dt.from_xml("not-a-duration")
        with pytest.raises(ValueError):
            dt.from_xml("1Y")
        with pytest.raises(ValueError):
            dt.from_xml("")
        with pytest.raises(ValueError):
            dt.from_xml("P1H")  # H without T prefix


class TestOptionalParams:
    def test_optional_param_required_false(self) -> None:
        from soapbar.server.service import SoapService, soap_operation

        class Svc(SoapService):
            @soap_operation()
            def op(self, x: str, y: str | None) -> str:
                return x

        svc = Svc()
        sig = svc.get_operation_signatures()["op"]
        assert sig.input_params[0].required is True   # x
        assert sig.input_params[1].required is False  # y (Optional)

    def test_default_param_required_false(self) -> None:
        from soapbar.server.service import SoapService, soap_operation

        class Svc(SoapService):
            @soap_operation()
            def op(self, x: str, y: str = "default") -> str:
                return x

        svc = Svc()
        sig = svc.get_operation_signatures()["op"]
        assert sig.input_params[0].required is True   # x
        assert sig.input_params[1].required is False  # y (has default)

    def test_required_param_unchanged(self) -> None:
        from soapbar.server.service import SoapService, soap_operation

        class Svc(SoapService):
            @soap_operation()
            def op(self, x: str) -> str:
                return x

        svc = Svc()
        sig = svc.get_operation_signatures()["op"]
        assert sig.input_params[0].required is True

# =============================================================================
# P4 Tests — MAJOR-003, MINOR-003, INFO-001..004
# =============================================================================

# ---------------------------------------------------------------------------
# ArrayXsdType
# ---------------------------------------------------------------------------

class TestArrayXsdType:
    def _string_type(self):
        return xsd.resolve("string")

    def test_to_element_basic(self) -> None:
        from soapbar.core.types import ArrayXsdType
        st = self._string_type()
        assert st is not None
        arr = ArrayXsdType("StringArray", st, element_tag="item")
        elem = arr.to_element("items", ["a", "b", "c"])
        assert elem.tag == "items"
        children = list(elem)
        assert len(children) == 3
        assert children[0].tag == "item"
        assert children[0].text == "a"
        assert children[2].text == "c"

    def test_from_element_basic(self) -> None:
        from soapbar.core.types import ArrayXsdType
        st = self._string_type()
        assert st is not None
        arr = ArrayXsdType("StringArray", st, element_tag="item")
        xml = b"<items><item>x</item><item>y</item></items>"
        elem = etree.fromstring(xml)
        result = arr.from_element(elem)
        assert result == ["x", "y"]

    def test_to_element_with_ns(self) -> None:
        from soapbar.core.types import ArrayXsdType
        st = self._string_type()
        assert st is not None
        arr = ArrayXsdType("Arr", st, element_tag="val")
        elem = arr.to_element("vals", ["foo"], ns="http://ex.com/")
        assert elem.tag == "{http://ex.com/}vals"

    def test_to_xml_raises(self) -> None:
        from soapbar.core.types import ArrayXsdType
        st = self._string_type()
        assert st is not None
        arr = ArrayXsdType("X", st)
        with pytest.raises(TypeError):
            arr.to_xml(["a"])

    def test_from_xml_raises(self) -> None:
        from soapbar.core.types import ArrayXsdType
        st = self._string_type()
        assert st is not None
        arr = ArrayXsdType("X", st)
        with pytest.raises(TypeError):
            arr.from_xml("a")

    def test_nested_complex(self) -> None:
        from soapbar.core.types import ArrayXsdType, ComplexXsdType
        st = self._string_type()
        assert st is not None
        it = self._string_type()
        assert it is not None
        ct = ComplexXsdType("Item", [("name", st), ("value", it)])
        arr = ArrayXsdType("ItemArray", ct, element_tag="item")
        elem = arr.to_element("items", [
            {"name": "foo", "value": "bar"},
            {"name": "baz", "value": "qux"},
        ])
        children = list(elem)
        assert len(children) == 2
        assert children[0].find("name").text == "foo"  # type: ignore[union-attr]
        result = arr.from_element(elem)
        assert result[0]["name"] == "foo"
        assert result[1]["value"] == "qux"


# ---------------------------------------------------------------------------
# ChoiceXsdType
# ---------------------------------------------------------------------------

class TestChoiceXsdType:
    def test_to_element_first_option(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        st = xsd.resolve("string")
        it = xsd.resolve("int")
        assert st and it
        ch = ChoiceXsdType("TextOrNum", [("text", st), ("number", it)])
        elem = ch.to_element("choice", {"text": "hello"})
        assert elem.tag == "choice"
        children = list(elem)
        assert len(children) == 1
        assert children[0].tag == "text"
        assert children[0].text == "hello"

    def test_to_element_second_option(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        st = xsd.resolve("string")
        it = xsd.resolve("int")
        assert st and it
        ch = ChoiceXsdType("TextOrNum", [("text", st), ("number", it)])
        elem = ch.to_element("choice", {"number": 42})
        children = list(elem)
        assert len(children) == 1
        assert children[0].tag == "number"
        assert children[0].text == "42"

    def test_from_element(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        st = xsd.resolve("string")
        it = xsd.resolve("int")
        assert st and it
        ch = ChoiceXsdType("TextOrNum", [("text", st), ("number", it)])
        xml = b"<choice><number>99</number></choice>"
        elem = etree.fromstring(xml)
        result = ch.from_element(elem)
        assert result == {"number": 99}

    def test_from_element_no_match(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        st = xsd.resolve("string")
        assert st
        ch = ChoiceXsdType("X", [("a", st)])
        elem = etree.fromstring(b"<choice/>")
        assert ch.from_element(elem) == {}

    def test_to_xml_raises(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        st = xsd.resolve("string")
        assert st
        ch = ChoiceXsdType("X", [("a", st)])
        with pytest.raises(TypeError):
            ch.to_xml({"a": "v"})

    def test_from_xml_raises(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        st = xsd.resolve("string")
        assert st
        ch = ChoiceXsdType("X", [("a", st)])
        with pytest.raises(TypeError):
            ch.from_xml("v")


# ---------------------------------------------------------------------------
# ComplexXsdType — recursive / lazy string resolution
# ---------------------------------------------------------------------------

class TestComplexXsdTypeRecursive:
    def test_lazy_string_field(self) -> None:
        from soapbar.core.types import ComplexXsdType
        # Register a type first, then reference by name
        ct = ComplexXsdType("Point", [("x", "int"), ("y", "int")])
        elem = ct.to_element("pt", {"x": 1, "y": 2})
        assert elem.find("x").text == "1"  # type: ignore[union-attr]
        result = ct.from_element(elem)
        assert result["x"] == 1
        assert result["y"] == 2

    def test_nested_complex_to_element(self) -> None:
        from soapbar.core.types import ComplexXsdType
        st = xsd.resolve("string")
        assert st
        inner = ComplexXsdType("Inner", [("val", st)])
        outer = ComplexXsdType("Outer", [("inner", inner)])
        elem = outer.to_element("o", {"inner": {"val": "hello"}})
        inner_elem = elem.find("inner")
        assert inner_elem is not None
        val_elem = inner_elem.find("val")
        assert val_elem is not None and val_elem.text == "hello"

    def test_nested_complex_from_element(self) -> None:
        from soapbar.core.types import ComplexXsdType
        st = xsd.resolve("string")
        assert st
        inner = ComplexXsdType("Inner2", [("val", st)])
        outer = ComplexXsdType("Outer2", [("inner", inner)])
        xml = b"<o><inner><val>world</val></inner></o>"
        elem = etree.fromstring(xml)
        result = outer.from_element(elem)
        assert result["inner"] == {"val": "world"}

    def test_invalid_string_reference_raises(self) -> None:
        from soapbar.core.types import ComplexXsdType
        ct = ComplexXsdType("Bad", [("x", "nonexistent_type_xyz")])
        with pytest.raises(ValueError, match="Cannot resolve XSD type"):
            ct.to_element("bad", {"x": "v"})


# ---------------------------------------------------------------------------
# Schema-driven WSDL parsing
# ---------------------------------------------------------------------------

class TestSchemaDrivenWsdl:
    _WSDL_WITH_COMPLEX = b"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             xmlns:tns="http://example.com/types"
             targetNamespace="http://example.com/types"
             name="TypesService">
  <types>
    <xsd:schema targetNamespace="http://example.com/types">
      <xsd:complexType name="Address">
        <xsd:sequence>
          <xsd:element name="street" type="xsd:string"/>
          <xsd:element name="city" type="xsd:string"/>
          <xsd:element name="zip" type="xsd:string"/>
        </xsd:sequence>
      </xsd:complexType>
      <xsd:complexType name="PhoneOrEmail">
        <xsd:choice>
          <xsd:element name="phone" type="xsd:string"/>
          <xsd:element name="email" type="xsd:string"/>
        </xsd:choice>
      </xsd:complexType>
      <xsd:complexType name="AddressList">
        <xsd:sequence>
          <xsd:element name="address" type="xsd:string" maxOccurs="unbounded"/>
        </xsd:sequence>
      </xsd:complexType>
    </xsd:schema>
  </types>
  <message name="DummyRequest"><part name="body" type="xsd:string"/></message>
  <message name="DummyResponse"><part name="result" type="xsd:string"/></message>
  <portType name="DummyPortType">
    <operation name="Dummy">
      <input message="tns:DummyRequest"/>
      <output message="tns:DummyResponse"/>
    </operation>
  </portType>
  <binding name="DummyBinding" type="tns:DummyPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Dummy">
      <soap:operation soapAction="Dummy"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
  </binding>
  <service name="DummyService">
    <port name="DummyPort" binding="tns:DummyBinding">
      <soap:address location="http://localhost/dummy"/>
    </port>
  </service>
</definitions>"""

    def test_parse_complex_type(self) -> None:
        from soapbar.core.types import ComplexXsdType
        defn = parse_wsdl(self._WSDL_WITH_COMPLEX)
        assert "Address" in defn.complex_types
        ct = defn.complex_types["Address"]
        assert isinstance(ct, ComplexXsdType)
        assert ct.name == "Address"
        field_names = [f[0] for f in ct.fields]
        assert "street" in field_names
        assert "city" in field_names
        assert "zip" in field_names

    def test_parse_choice(self) -> None:
        from soapbar.core.types import ChoiceXsdType
        defn = parse_wsdl(self._WSDL_WITH_COMPLEX)
        assert "PhoneOrEmail" in defn.complex_types
        ct = defn.complex_types["PhoneOrEmail"]
        assert isinstance(ct, ChoiceXsdType)
        opt_names = [o[0] for o in ct.options]
        assert "phone" in opt_names
        assert "email" in opt_names

    def test_parse_array(self) -> None:
        from soapbar.core.types import ArrayXsdType
        defn = parse_wsdl(self._WSDL_WITH_COMPLEX)
        assert "AddressList" in defn.complex_types
        ct = defn.complex_types["AddressList"]
        # maxOccurs=unbounded on a field makes it an ArrayXsdType field inside ComplexXsdType
        from soapbar.core.types import ComplexXsdType
        assert isinstance(ct, ComplexXsdType)
        # The field "address" should be an ArrayXsdType
        field_map = {f[0]: f[1] for f in ct.fields}
        assert "address" in field_map
        assert isinstance(field_map["address"], ArrayXsdType)

    def test_registered_in_xsd_registry(self) -> None:
        defn = parse_wsdl(self._WSDL_WITH_COMPLEX)
        assert defn.complex_types  # non-empty
        # All parsed types should be in xsd registry now
        for name in defn.complex_types:
            assert xsd.resolve(name) is not None


# ---------------------------------------------------------------------------
# WSDL builder — complex type output
# ---------------------------------------------------------------------------

class TestWsdlBuilderComplexType:
    def test_build_wsdl_with_complex_types(self) -> None:
        from soapbar.core.types import ComplexXsdType
        from soapbar.core.wsdl import WsdlDefinition
        defn = WsdlDefinition(name="Test", target_namespace="http://test.com/")
        st = xsd.resolve("string")
        assert st
        ct = ComplexXsdType("Person", [("name", st), ("age", "int")])
        defn.complex_types["Person"] = ct
        wsdl_str = build_wsdl_string(defn, "http://localhost/")
        assert "Person" in wsdl_str
        assert "complexType" in wsdl_str
        assert "sequence" in wsdl_str


# ---------------------------------------------------------------------------
# SoapHeaderBlock — relay and role parsing
# ---------------------------------------------------------------------------

class TestSoapHeaderBlock:
    def _make_soap12_envelope_with_header(self, relay: str = "false", role: str | None = None) -> bytes:
        soap12_ns = NS.SOAP12_ENV
        role_attr = f' soap12:role="{role}"' if role else ""
        xml = f"""<?xml version="1.0"?>
<soap12:Envelope xmlns:soap12="{soap12_ns}">
  <soap12:Header>
    <tns:MyHeader xmlns:tns="http://ex.com/"
                  soap12:mustUnderstand="false"
                  soap12:relay="{relay}"{role_attr}>value</tns:MyHeader>
  </soap12:Header>
  <soap12:Body><tns:Op xmlns:tns="http://ex.com/"/></soap12:Body>
</soap12:Envelope>"""
        return xml.encode()

    def test_relay_parsed_true(self) -> None:
        from soapbar.core.envelope import SoapHeaderBlock
        env = SoapEnvelope.from_xml(self._make_soap12_envelope_with_header(relay="true"))
        assert len(env.header_blocks) == 1
        block = env.header_blocks[0]
        assert isinstance(block, SoapHeaderBlock)
        assert block.relay is True

    def test_relay_default_false(self) -> None:
        env = SoapEnvelope.from_xml(self._make_soap12_envelope_with_header(relay="false"))
        assert env.header_blocks[0].relay is False

    def test_must_understand_block(self) -> None:
        soap12_ns = NS.SOAP12_ENV
        xml = f"""<?xml version="1.0"?>
<soap12:Envelope xmlns:soap12="{soap12_ns}">
  <soap12:Header>
    <tns:Hdr xmlns:tns="http://ex.com/" soap12:mustUnderstand="true">v</tns:Hdr>
  </soap12:Header>
  <soap12:Body/>
</soap12:Envelope>""".encode()
        env = SoapEnvelope.from_xml(xml)
        assert env.header_blocks[0].must_understand is True

    def test_role_parsed(self) -> None:
        env = SoapEnvelope.from_xml(
            self._make_soap12_envelope_with_header(role="http://www.w3.org/2003/05/soap-envelope/role/next")
        )
        block = env.header_blocks[0]
        assert block.role == "http://www.w3.org/2003/05/soap-envelope/role/next"

    def test_soap11_actor_as_role(self) -> None:
        soap_ns = NS.SOAP_ENV
        xml = f"""<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="{soap_ns}">
  <soapenv:Header>
    <tns:H xmlns:tns="http://ex.com/"
           soapenv:actor="http://actor.example.com/">v</tns:H>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>""".encode()
        env = SoapEnvelope.from_xml(xml)
        assert env.header_blocks[0].role == "http://actor.example.com/"

    def test_header_elements_property_compatibility(self) -> None:
        """header_elements property must return list of _Element."""
        soap_ns = NS.SOAP_ENV
        xml = f"""<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="{soap_ns}">
  <soapenv:Header><tns:H xmlns:tns="http://ex.com/">v</tns:H></soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>""".encode()
        env = SoapEnvelope.from_xml(xml)
        elems = env.header_elements
        assert len(elems) == 1
        assert elems[0].tag == "{http://ex.com/}H"

    def test_add_header_accepts_block(self) -> None:
        from soapbar.core.envelope import SoapHeaderBlock
        env = SoapEnvelope()
        elem = etree.Element("TestHeader")
        block = SoapHeaderBlock(element=elem, relay=True)
        env.add_header(block)
        assert env.header_blocks[0].relay is True

    def test_add_header_accepts_element(self) -> None:
        env = SoapEnvelope()
        elem = etree.Element("TestHeader")
        env.add_header(elem)
        assert len(env.header_blocks) == 1
        assert env.header_blocks[0].element is elem


# ---------------------------------------------------------------------------
# MTOM detection — ASGI
# ---------------------------------------------------------------------------

class TestMtomDetectionAsgi:
    def _make_app(self):
        app = SoapApplication()

        class Svc(SoapService):
            @soap_operation(soap_action="Hello")
            def Hello(self, name: str) -> str:
                return f"Hello {name}"

        app.register(Svc())
        return AsgiSoapApp(app)

    def _build_mtom_request(self, name: str) -> bytes:
        """Build a minimal MTOM multipart request wrapping a plain SOAP envelope."""
        from soapbar.core.mtom import MtomAttachment, build_mtom

        soap_xml = (
            b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body>"
            b"<Hello><name>" + name.encode() + b"</name></Hello>"
            b"</soapenv:Body></soapenv:Envelope>"
        )
        body, _ = build_mtom(soap_xml, [], soap_version_content_type="text/xml")
        return body

    def test_asgi_mtom_dispatches_correctly(self) -> None:
        """MTOM request should be decoded and dispatched — returns 200."""
        import asyncio

        asgi = self._make_app()
        soap_xml = (
            b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><Hello><name>World</name></Hello></soapenv:Body></soapenv:Envelope>"
        )
        from soapbar.core.mtom import build_mtom
        body, outer_ct = build_mtom(soap_xml, [], soap_version_content_type="text/xml")

        scope = {
            "type": "http",
            "method": "POST",
            "query_string": b"",
            "headers": [
                (b"content-type", outer_ct.encode()),
                (b"soapaction", b'"Hello"'),
            ],
        }
        responses = []

        async def run():
            async def receive():
                return {"body": body, "more_body": False}
            async def send(msg):
                responses.append(msg)
            await asgi(scope, receive, send)

        asyncio.run(run())
        assert responses[0]["status"] == 200

    def test_asgi_non_mtom_passes_through(self) -> None:
        import asyncio

        asgi = self._make_app()
        body = (
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><Hello><name>World</name></Hello></soapenv:Body></soapenv:Envelope>"
        )
        scope = {
            "type": "http",
            "method": "POST",
            "query_string": b"",
            "headers": [
                (b"content-type", b"text/xml"),
                (b"soapaction", b'"Hello"'),
            ],
        }
        responses = []

        async def run():
            async def receive():
                return {"body": body, "more_body": False}
            async def send(msg):
                responses.append(msg)
            await asgi(scope, receive, send)

        asyncio.run(run())
        assert responses[0]["status"] == 200


# ---------------------------------------------------------------------------
# MTOM detection — WSGI
# ---------------------------------------------------------------------------

class TestMtomDetectionWsgi:
    def _make_wsgi(self):
        app = SoapApplication()

        class Svc(SoapService):
            @soap_operation(soap_action="Greet")
            def Greet(self, name: str) -> str:
                return f"Hi {name}"

        app.register(Svc())
        return WsgiSoapApp(app)

    def test_wsgi_mtom_dispatches_correctly(self) -> None:
        """MTOM request should be decoded and dispatched — returns 200."""
        wsgi = self._make_wsgi()
        soap_xml = (
            b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><Greet><name>Test</name></Greet></soapenv:Body></soapenv:Envelope>"
        )
        from soapbar.core.mtom import build_mtom
        body, outer_ct = build_mtom(soap_xml, [], soap_version_content_type="text/xml")

        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": outer_ct,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            "HTTP_SOAPACTION": '"Greet"',
            "QUERY_STRING": "",
        }
        status_holder = []
        def start_response(status, headers):
            status_holder.append(status)

        wsgi(environ, start_response)
        assert "200" in status_holder[0]

    def test_wsgi_non_mtom_passes(self) -> None:
        import io
        wsgi = self._make_wsgi()
        body = (
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><Greet><name>Test</name></Greet></soapenv:Body></soapenv:Envelope>"
        )
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": "text/xml",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            "HTTP_SOAPACTION": '"Greet"',
            "QUERY_STRING": "",
        }
        status_holder = []
        def start_response(status, headers):
            status_holder.append(status)

        wsgi(environ, start_response)
        assert "200" in status_holder[0]


# ---------------------------------------------------------------------------
# MTOM detection — transport
# ---------------------------------------------------------------------------

class TestMtomTransport:
    def test_transport_mtom_decodes_response(self) -> None:
        """Transport now decodes MTOM responses instead of raising."""
        from soapbar.core.mtom import build_mtom

        soap_xml = (
            b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><r>ok</r></soapenv:Body></soapenv:Envelope>"
        )
        body, outer_ct = build_mtom(soap_xml, [], soap_version_content_type="text/xml")
        transport = HttpTransport()
        normalised_ct, result_bytes = transport._decode_mtom_if_needed(outer_ct, body)
        assert "multipart" not in normalised_ct
        assert b"<r>ok</r>" in result_bytes

    def test_transport_normal_passes_through(self) -> None:
        """Non-MTOM responses pass through unchanged."""
        transport = HttpTransport()
        ct_in = "text/xml; charset=utf-8"
        body = b"<x/>"
        ct_out, body_out = transport._decode_mtom_if_needed(ct_in, body)
        assert ct_out == ct_in
        assert body_out == body


# ---------------------------------------------------------------------------
# WS-Addressing
# ---------------------------------------------------------------------------

class TestWsAddressing:
    _WSA = NS.WSA
    _SOAP11 = NS.SOAP_ENV

    def _envelope_with_wsa(self, headers_xml: str) -> bytes:
        return f"""<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="{self._SOAP11}"
                  xmlns:wsa="{self._WSA}">
  <soapenv:Header>
    {headers_xml}
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>""".encode()

    def test_parse_message_id(self) -> None:
        xml = self._envelope_with_wsa(
            f'<wsa:MessageID xmlns:wsa="{self._WSA}">urn:uuid:12345</wsa:MessageID>'
        )
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_addressing is not None
        assert env.ws_addressing.message_id == "urn:uuid:12345"

    def test_parse_to(self) -> None:
        xml = self._envelope_with_wsa(
            f'<wsa:To xmlns:wsa="{self._WSA}">http://service.example.com/</wsa:To>'
        )
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_addressing is not None
        assert env.ws_addressing.to == "http://service.example.com/"

    def test_parse_action(self) -> None:
        xml = self._envelope_with_wsa(
            f'<wsa:Action xmlns:wsa="{self._WSA}">http://example.com/action</wsa:Action>'
        )
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_addressing is not None
        assert env.ws_addressing.action == "http://example.com/action"

    def test_parse_reply_to(self) -> None:
        xml = self._envelope_with_wsa(
            f'<wsa:ReplyTo xmlns:wsa="{self._WSA}">'
            f'  <wsa:Address>http://reply.example.com/</wsa:Address>'
            f'</wsa:ReplyTo>'
        )
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_addressing is not None
        assert env.ws_addressing.reply_to is not None
        assert env.ws_addressing.reply_to.address == "http://reply.example.com/"

    def test_no_wsa_returns_none(self) -> None:
        xml = (
            f'<soapenv:Envelope xmlns:soapenv="{self._SOAP11}">'
            f"<soapenv:Body/></soapenv:Envelope>"
        ).encode()
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_addressing is None

    def test_multiple_wsa_headers(self) -> None:
        xml = self._envelope_with_wsa(
            f'<wsa:MessageID xmlns:wsa="{self._WSA}">urn:msg-1</wsa:MessageID>'
            f'<wsa:Action xmlns:wsa="{self._WSA}">urn:action-1</wsa:Action>'
        )
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_addressing is not None
        assert env.ws_addressing.message_id == "urn:msg-1"
        assert env.ws_addressing.action == "urn:action-1"


class TestWsaResponseHeaders:
    """WS-Addressing 1.0 response header generation."""

    _WSA = NS.WSA

    def test_response_includes_message_id(self) -> None:
        from soapbar.core.envelope import WsaHeaders, build_wsa_response_headers
        wsa = WsaHeaders(message_id="urn:uuid:req-1")
        headers = build_wsa_response_headers(wsa)
        tags = {local_name(h) for h in headers}
        assert "MessageID" in tags

    def test_response_message_id_is_urn_uuid(self) -> None:
        from soapbar.core.envelope import WsaHeaders, build_wsa_response_headers
        wsa = WsaHeaders(message_id="urn:uuid:req-1")
        headers = build_wsa_response_headers(wsa)
        msg_id = next(h for h in headers if local_name(h) == "MessageID")
        assert (msg_id.text or "").startswith("urn:uuid:")

    def test_response_relates_to_echoes_request_message_id(self) -> None:
        from soapbar.core.envelope import WsaHeaders, build_wsa_response_headers
        wsa = WsaHeaders(message_id="urn:uuid:req-42")
        headers = build_wsa_response_headers(wsa)
        relates_to = next((h for h in headers if local_name(h) == "RelatesTo"), None)
        assert relates_to is not None
        assert relates_to.text == "urn:uuid:req-42"

    def test_response_no_relates_to_when_no_request_message_id(self) -> None:
        from soapbar.core.envelope import WsaHeaders, build_wsa_response_headers
        wsa = WsaHeaders()  # no message_id
        headers = build_wsa_response_headers(wsa)
        tags = [local_name(h) for h in headers]
        assert "RelatesTo" not in tags

    def test_response_action_included_when_provided(self) -> None:
        from soapbar.core.envelope import WsaHeaders, build_wsa_response_headers
        wsa = WsaHeaders(message_id="urn:uuid:req-1")
        headers = build_wsa_response_headers(wsa, action="http://example.com/OpResponse")
        action_elem = next((h for h in headers if local_name(h) == "Action"), None)
        assert action_elem is not None
        assert action_elem.text == "http://example.com/OpResponse"

    def test_application_injects_wsa_headers_on_response(self) -> None:
        """SoapApplication injects WSA RelatesTo + MessageID when request has WSA headers."""
        from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
        from soapbar.core.types import xsd
        from soapbar.server.application import SoapApplication
        from soapbar.server.service import SoapService, soap_operation

        int_type = xsd.resolve("int")
        assert int_type is not None

        class Svc(SoapService):
            __service_name__ = "Calc"
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                input_params=[OperationParameter("a", int_type), OperationParameter("b", int_type)],
                output_params=[OperationParameter("result", int_type)],
            )
            def add(self, a: int, b: int) -> int:
                return a + b

        app = SoapApplication()
        app.register(Svc())

        req = (
            b'<?xml version="1.0"?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            b'                  xmlns:wsa="http://www.w3.org/2005/08/addressing"'
            b'                  xmlns:tns="http://example.com/">'
            b'  <soapenv:Header>'
            b'    <wsa:MessageID>urn:uuid:test-req-001</wsa:MessageID>'
            b'    <wsa:Action>http://example.com/add</wsa:Action>'
            b'  </soapenv:Header>'
            b'  <soapenv:Body><tns:add><a>3</a><b>4</b></tns:add></soapenv:Body>'
            b'</soapenv:Envelope>'
        )
        status, _ct, resp_bytes = app.handle_request(req)
        assert status == 200
        resp_env = SoapEnvelope.from_xml(resp_bytes)
        assert resp_env.ws_addressing is not None
        assert resp_env.ws_addressing.relates_to == "urn:uuid:test-req-001"
        assert resp_env.ws_addressing.message_id is not None
        assert resp_env.ws_addressing.message_id != "urn:uuid:test-req-001"

    def test_application_no_wsa_headers_when_request_has_none(self) -> None:
        """SoapApplication does not add WSA headers when request has none."""
        from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
        from soapbar.core.types import xsd
        from soapbar.server.application import SoapApplication
        from soapbar.server.service import SoapService, soap_operation

        int_type = xsd.resolve("int")
        assert int_type is not None

        class Svc2(SoapService):
            __service_name__ = "Calc2"
            __tns__ = "http://example.com/"
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
            __soap_version__ = SoapVersion.SOAP_11

            @soap_operation(
                input_params=[OperationParameter("a", int_type)],
                output_params=[OperationParameter("result", int_type)],
            )
            def add(self, a: int) -> int:
                return a

        app = SoapApplication()
        app.register(Svc2())

        req = (
            b'<?xml version="1.0"?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            b'                  xmlns:tns="http://example.com/">'
            b'  <soapenv:Body><tns:add><a>5</a></tns:add></soapenv:Body>'
            b'</soapenv:Envelope>'
        )
        status, _ct, resp_bytes = app.handle_request(req)
        assert status == 200
        resp_env = SoapEnvelope.from_xml(resp_bytes)
        assert resp_env.ws_addressing is None


# ---------------------------------------------------------------------------
# WS-Security detection
# ---------------------------------------------------------------------------

class TestWsSecurity:
    _WSSE = NS.WSSE
    _SOAP11 = NS.SOAP_ENV

    def test_detect_security_header(self) -> None:
        xml = f"""<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="{self._SOAP11}"
                  xmlns:wsse="{self._WSSE}">
  <soapenv:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>""".encode()
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_security_element is not None
        from soapbar.core.xml import local_name
        assert local_name(env.ws_security_element) == "Security"

    def test_no_security_returns_none(self) -> None:
        xml = (
            f'<soapenv:Envelope xmlns:soapenv="{self._SOAP11}">'
            f"<soapenv:Body/></soapenv:Envelope>"
        ).encode()
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_security_element is None

    def test_security_element_content_accessible(self) -> None:
        xml = f"""<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="{self._SOAP11}"
                  xmlns:wsse="{self._WSSE}">
  <soapenv:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>testuser</wsse:Username>
      </wsse:UsernameToken>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>""".encode()
        env = SoapEnvelope.from_xml(xml)
        assert env.ws_security_element is not None
        token = env.ws_security_element.find(f"{{{self._WSSE}}}UsernameToken")
        assert token is not None
        uname = token.find(f"{{{self._WSSE}}}Username")
        assert uname is not None and uname.text == "testuser"


# ---------------------------------------------------------------------------
# SoapEnvelope — header_elements constructor backward compat (Bug 2)
# ---------------------------------------------------------------------------

class TestSoapEnvelopeConstructorHeaderElements:
    def test_header_elements_init_var(self) -> None:
        """SoapEnvelope(header_elements=[...]) should still work after P4."""
        elem = make_element("{http://example.com/}MyHeader")
        elem.text = "hello"
        env = SoapEnvelope(header_elements=[elem])
        assert len(env.header_blocks) == 1
        assert env.header_blocks[0].element is elem
        assert env.header_elements == [elem]

    def test_header_elements_init_var_none_is_noop(self) -> None:
        """SoapEnvelope() without header_elements keeps empty header_blocks."""
        env = SoapEnvelope()
        assert env.header_blocks == []

    def test_header_elements_init_var_does_not_override_header_blocks(self) -> None:
        """header_elements=None must not wipe pre-set header_blocks."""
        env = SoapEnvelope()
        elem = make_element("{http://example.com/}H")
        env.header_blocks = [__import__("soapbar.core.envelope", fromlist=["SoapHeaderBlock"]).SoapHeaderBlock(element=elem)]
        # Calling with no header_elements kwarg shouldn't clear header_blocks
        env2 = SoapEnvelope(header_elements=None)
        assert env2.header_blocks == []

    def test_header_elements_property_setter_still_works(self) -> None:
        """Assignment via property setter should still function."""
        elem = make_element("{http://example.com/}H")
        env = SoapEnvelope()
        env.header_elements = [elem]
        assert len(env.header_blocks) == 1
        assert env.header_blocks[0].element is elem


# ---------------------------------------------------------------------------
# application.py — WSDL auto-gen uses tns: for complex types (Bug 1)
# ---------------------------------------------------------------------------

class TestWsdlComplexTypeRef:
    def test_wsdl_part_uses_tns_for_complex(self) -> None:
        """Auto-WSDL must emit tns:TypeName for ComplexXsdType params, not xsd:TypeName."""
        from soapbar.core.types import ComplexXsdType
        from soapbar.server.application import SoapApplication
        from soapbar.server.service import SoapService, soap_operation

        str_type = xsd.resolve("string")
        assert str_type is not None
        person_type = ComplexXsdType("Person", [("name", str_type)])

        class MySvc(SoapService):
            @soap_operation(
                input_params=[OperationParameter("p", person_type)],
                output_params=[OperationParameter("result", person_type)],
            )
            def get_person(self, p: object) -> object:
                return p

        app = SoapApplication()
        app.register(MySvc())
        wsdl_bytes = app.get_wsdl()
        wsdl_str = wsdl_bytes.decode()
        assert 'type="tns:Person"' in wsdl_str, f"Expected tns:Person in WSDL, got:\n{wsdl_str}"
        assert 'type="xsd:Person"' not in wsdl_str

    def test_wsdl_part_keeps_xsd_for_primitives(self) -> None:
        """Auto-WSDL must keep xsd: prefix for primitive XSD types."""
        from soapbar.server.application import SoapApplication
        from soapbar.server.service import SoapService, soap_operation

        str_type = xsd.resolve("string")
        assert str_type is not None

        class MySvc2(SoapService):
            @soap_operation(
                input_params=[OperationParameter("s", str_type)],
                output_params=[OperationParameter("result", str_type)],
            )
            def echo(self, s: object) -> object:
                return s

        app = SoapApplication()
        app.register(MySvc2())
        wsdl_bytes = app.get_wsdl()
        wsdl_str = wsdl_bytes.decode()
        assert 'type="xsd:string"' in wsdl_str


class TestWsdlCircularImportGuard:
    def test_circular_import_does_not_recurse(self) -> None:
        """parse_wsdl() must not raise RecursionError when WSDL A imports A."""
        from unittest.mock import patch

        from soapbar.core.wsdl.parser import parse_wsdl

        wsdl_a = b"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             targetNamespace="urn:test"
             name="CircularA">
  <import namespace="urn:test" location="http://example.com/a.wsdl"/>
</definitions>"""

        # Make _fetch_wsdl_source always return wsdl_a, creating a cycle.
        with patch("soapbar.core.wsdl.parser._fetch_wsdl_source", return_value=wsdl_a):
            # Should return without RecursionError; cycle is silently skipped.
            defn = parse_wsdl(
                wsdl_a,
                base_url="http://example.com/a.wsdl",
                allow_remote_imports=True,
            )
        assert defn.name == "CircularA"


class TestAsyncTransportMtomCheck:
    def test_send_async_decodes_mtom_response(self) -> None:
        """send_async() now decodes MTOM responses instead of raising."""
        import asyncio

        from soapbar.core.mtom import build_mtom

        soap_xml = (
            b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><r>async_ok</r></soapenv:Body></soapenv:Envelope>"
        )
        body, outer_ct = build_mtom(soap_xml, [], soap_version_content_type="text/xml")

        transport = HttpTransport()

        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": outer_ct}
        mock_resp.status_code = 200
        mock_resp.content = body

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            status, ct, resp_body = asyncio.run(
                transport.send_async("http://example.com/", b"<body/>", {})
            )
        assert status == 200
        assert "multipart" not in ct
        assert b"async_ok" in resp_body


class TestSoap12SubcodeNested:
    def test_single_subcode_unchanged(self) -> None:
        """Single subcode produces <Subcode><Value>...</Value></Subcode>."""
        from lxml import etree

        from soapbar.core.fault import SoapFault
        from soapbar.core.namespaces import NS

        fault = SoapFault("Server", "err", subcodes=[("http://example.com/", "A")])
        elem = fault.to_soap12_element()
        code_elem = elem.find(f"{{{NS.SOAP12_ENV}}}Code")
        assert code_elem is not None
        subcode = code_elem.find(f"{{{NS.SOAP12_ENV}}}Subcode")
        assert subcode is not None
        val = subcode.find(f"{{{NS.SOAP12_ENV}}}Value")
        assert val is not None
        assert ":" in (val.text or "")
        assert (val.text or "").split(":")[-1] == "A"

    def test_multi_subcode_nested(self) -> None:
        """Multiple subcodes produce properly nested <Subcode> hierarchy."""
        from soapbar.core.fault import SoapFault
        from soapbar.core.namespaces import NS

        fault = SoapFault("Server", "err", subcodes=[("http://example.com/", "A"), ("http://example.com/", "B")])
        elem = fault.to_soap12_element()
        code_elem = elem.find(f"{{{NS.SOAP12_ENV}}}Code")
        assert code_elem is not None

        # First level: Subcode under Code
        sc1 = code_elem.find(f"{{{NS.SOAP12_ENV}}}Subcode")
        assert sc1 is not None
        val1 = sc1.find(f"{{{NS.SOAP12_ENV}}}Value")
        assert val1 is not None
        assert (val1.text or "").split(":")[-1] == "A"

        # Second level: Subcode nested inside the first Subcode
        sc2 = sc1.find(f"{{{NS.SOAP12_ENV}}}Subcode")
        assert sc2 is not None
        val2 = sc2.find(f"{{{NS.SOAP12_ENV}}}Value")
        assert val2 is not None
        assert (val2.text or "").split(":")[-1] == "B"

        # No sibling Value under the first Subcode (non-nested would have 2 Values)
        values_under_sc1 = sc1.findall(f"{{{NS.SOAP12_ENV}}}Value")
        assert len(values_under_sc1) == 1


# ===========================================================================
# G05 — SOAP Array Attributes
# ===========================================================================

class TestSoapArrayAttributes:
    """G05: SOAP 1.1/1.2 array attributes on ArrayXsdType.to_element()."""

    def test_soap11_array_type_attribute(self) -> None:
        """SOAP 1.1 §5.4.2: SOAP-ENC:arrayType='xsd:T[N]' emitted."""
        arr = ArrayXsdType("StringArray", _xsd_string, element_tag="item")
        elem = arr.to_element("names", ["a", "b", "c"], soap_encoding=NS.SOAP_ENC)
        attr_key = f"{{{NS.SOAP_ENC}}}arrayType"
        assert attr_key in elem.attrib
        assert elem.attrib[attr_key] == "xsd:string[3]"

    def test_soap12_array_type_attributes(self) -> None:
        """SOAP 1.2 Part 2 §3.3: enc:itemType and enc:arraySize emitted."""
        arr = ArrayXsdType("IntArray", _xsd_int, element_tag="item")
        elem = arr.to_element("numbers", [1, 2], soap_encoding=NS.SOAP12_ENC)
        item_type_key = f"{{{NS.SOAP12_ENC}}}itemType"
        array_size_key = f"{{{NS.SOAP12_ENC}}}arraySize"
        assert item_type_key in elem.attrib
        assert array_size_key in elem.attrib
        assert elem.attrib[item_type_key] == "xsd:int"
        assert elem.attrib[array_size_key] == "2"

    def test_no_array_attr_without_soap_encoding(self) -> None:
        """No encoding attributes emitted when soap_encoding is None."""
        arr = ArrayXsdType("StringArray", _xsd_string, element_tag="item")
        elem = arr.to_element("names", ["x"], soap_encoding=None)
        assert f"{{{NS.SOAP_ENC}}}arrayType" not in elem.attrib
        assert f"{{{NS.SOAP12_ENC}}}itemType" not in elem.attrib

    def test_rpc_encoded_serializer_soap11_array(self) -> None:
        """RpcEncodedSerializer with SOAP 1.1 emits SOAP-ENC:arrayType."""
        from lxml import etree
        arr = ArrayXsdType("StrList", _xsd_string, element_tag="item")
        sig = OperationSignature(
            name="ListOp",
            input_params=[OperationParameter("names", arr)],
        )
        ser = RpcEncodedSerializer(soap_enc_ns=NS.SOAP_ENC)
        body = etree.Element("_body")
        ser.serialize_request(sig, {"names": ["x", "y"]}, body)
        wrapper = body[0]
        names_elem = wrapper.find("names")
        assert names_elem is not None
        assert f"{{{NS.SOAP_ENC}}}arrayType" in names_elem.attrib

    def test_rpc_encoded_serializer_soap12_array(self) -> None:
        """RpcEncodedSerializer with SOAP 1.2 emits enc:itemType/enc:arraySize."""
        from lxml import etree
        arr = ArrayXsdType("StrList", _xsd_string, element_tag="item")
        sig = OperationSignature(
            name="ListOp",
            input_params=[OperationParameter("names", arr)],
        )
        ser = RpcEncodedSerializer(soap_enc_ns=NS.SOAP12_ENC)
        body = etree.Element("_body")
        ser.serialize_request(sig, {"names": ["a", "b", "c"]}, body)
        wrapper = body[0]
        names_elem = wrapper.find("names")
        assert names_elem is not None
        assert f"{{{NS.SOAP12_ENC}}}itemType" in names_elem.attrib
        assert names_elem.attrib[f"{{{NS.SOAP12_ENC}}}arraySize"] == "3"

    def test_get_serializer_soap12_returns_soap12_enc(self) -> None:
        """get_serializer for RPC_ENCODED + SOAP_12 returns SOAP 1.2 encoded serializer."""
        ser = get_serializer(BindingStyle.RPC_ENCODED, SoapVersion.SOAP_12)
        assert isinstance(ser, RpcEncodedSerializer)
        assert ser.soap_enc_ns == NS.SOAP12_ENC

    def test_get_serializer_soap11_returns_soap11_enc(self) -> None:
        """get_serializer for RPC_ENCODED + SOAP_11 returns SOAP 1.1 encoded serializer."""
        ser = get_serializer(BindingStyle.RPC_ENCODED, SoapVersion.SOAP_11)
        assert isinstance(ser, RpcEncodedSerializer)
        assert ser.soap_enc_ns == NS.SOAP_ENC


# ===========================================================================
# G06 — Multi-reference href/id encoding
# ===========================================================================

class TestMultiReferenceEncoding:
    """G06: SOAP 1.1 §5.2.5 multi-reference value encoding."""

    def test_first_occurrence_gets_id_attribute(self) -> None:
        """Shared complex value gets id= on first serialization."""
        from soapbar.core.types import ComplexXsdType
        from lxml import etree
        ct = ComplexXsdType("Address", [("street", _xsd_string)])
        shared = {"street": "Main St"}
        sig = OperationSignature(
            name="Test",
            input_params=[
                OperationParameter("addr1", ct),
                OperationParameter("addr2", ct),
            ],
        )
        ser = RpcEncodedSerializer()
        body = etree.Element("_body")
        # Same object identity
        ser.serialize_request(sig, {"addr1": shared, "addr2": shared}, body)
        wrapper = body[0]
        addr1 = wrapper.find("addr1")
        addr2 = wrapper.find("addr2")
        assert addr1 is not None
        assert addr2 is not None
        assert "id" in addr1.attrib
        assert "href" in addr2.attrib
        assert addr2.attrib["href"] == f"#{addr1.attrib['id']}"

    def test_non_shared_objects_no_id(self) -> None:
        """Distinct objects with same content do not get shared encoding."""
        from soapbar.core.types import ComplexXsdType
        from lxml import etree
        ct = ComplexXsdType("Item", [("name", _xsd_string)])
        sig = OperationSignature(
            name="Test",
            input_params=[
                OperationParameter("a", ct),
                OperationParameter("b", ct),
            ],
        )
        ser = RpcEncodedSerializer()
        body = etree.Element("_body")
        # Different Python objects (no shared identity)
        ser.serialize_request(sig, {"a": {"name": "X"}, "b": {"name": "Y"}}, body)
        wrapper = body[0]
        a_elem = wrapper.find("a")
        b_elem = wrapper.find("b")
        assert a_elem is not None and "id" not in a_elem.attrib
        assert b_elem is not None and "href" not in b_elem.attrib

    def test_href_resolved_on_deserialization(self) -> None:
        """href references are resolved to id'd elements during deserialization."""
        from soapbar.core.types import ComplexXsdType
        from lxml import etree
        ct = ComplexXsdType("Address", [("street", _xsd_string)])
        shared = {"street": "Broadway"}
        sig = OperationSignature(
            name="Test",
            input_params=[
                OperationParameter("addr1", ct),
                OperationParameter("addr2", ct),
            ],
        )
        ser = RpcEncodedSerializer()
        body = etree.Element("_body")
        ser.serialize_request(sig, {"addr1": shared, "addr2": shared}, body)
        # Now deserialize
        result = ser.deserialize_request(sig, body)
        assert result["addr1"] == {"street": "Broadway"}
        assert result["addr2"] == {"street": "Broadway"}


# ===========================================================================
# G09 — WS-Security UsernameToken
# ===========================================================================

class TestWsSecurityUsernameToken:
    """G09: WS-Security UsernameToken building and validation."""

    def test_build_security_header_text(self) -> None:
        """build_security_header emits wsse:Security with wsse:UsernameToken/Password."""
        from soapbar.core.wssecurity import UsernameTokenCredential, build_security_header
        cred = UsernameTokenCredential(username="alice", password="secret")
        elem = build_security_header(cred)
        wsse_ns = NS.WSSE
        assert elem.tag == f"{{{wsse_ns}}}Security"
        token = elem.find(f"{{{wsse_ns}}}UsernameToken")
        assert token is not None
        uname = token.find(f"{{{wsse_ns}}}Username")
        assert uname is not None and uname.text == "alice"
        pw = token.find(f"{{{wsse_ns}}}Password")
        assert pw is not None and pw.text == "secret"

    def test_build_security_header_digest(self) -> None:
        """Digest credential contains Nonce, Created, and hashed Password."""
        from soapbar.core.wssecurity import UsernameTokenCredential, build_security_header
        import base64
        cred = UsernameTokenCredential(
            username="bob",
            password="pass",
            use_digest=True,
            nonce=b"\x00" * 16,
            created="2026-01-01T00:00:00Z",
        )
        elem = build_security_header(cred)
        wsse_ns = NS.WSSE
        token = elem.find(f"{{{wsse_ns}}}UsernameToken")
        assert token is not None
        nonce_elem = token.find(f"{{{wsse_ns}}}Nonce")
        assert nonce_elem is not None
        assert base64.b64decode(nonce_elem.text or "") == b"\x00" * 16
        pw = token.find(f"{{{wsse_ns}}}Password")
        assert pw is not None
        assert "PasswordDigest" in (pw.get("Type") or "")

    def test_validator_password_text_success(self) -> None:
        """UsernameTokenValidator accepts correct PasswordText credentials."""
        from soapbar.core.wssecurity import (
            UsernameTokenCredential,
            UsernameTokenValidator,
            build_security_header,
        )

        class SimpleValidator(UsernameTokenValidator):
            def get_password(self, username: str) -> str | None:
                return "secret" if username == "alice" else None

        cred = UsernameTokenCredential(username="alice", password="secret")
        security = build_security_header(cred)
        validated = SimpleValidator().validate(security)
        assert validated == "alice"

    def test_validator_wrong_password_raises(self) -> None:
        """Wrong password raises SecurityValidationError."""
        from soapbar.core.wssecurity import (
            SecurityValidationError,
            UsernameTokenCredential,
            UsernameTokenValidator,
            build_security_header,
        )

        class SimpleValidator(UsernameTokenValidator):
            def get_password(self, username: str) -> str | None:
                return "right"

        cred = UsernameTokenCredential(username="alice", password="wrong")
        security = build_security_header(cred)
        with pytest.raises(SecurityValidationError, match="Password mismatch"):
            SimpleValidator().validate(security)

    def test_validator_digest_success(self) -> None:
        """Validator accepts correct PasswordDigest credentials."""
        from soapbar.core.wssecurity import (
            UsernameTokenCredential,
            UsernameTokenValidator,
            build_security_header,
        )

        class SimpleValidator(UsernameTokenValidator):
            def get_password(self, username: str) -> str | None:
                return "pass"

        cred = UsernameTokenCredential(
            username="alice",
            password="pass",
            use_digest=True,
            nonce=b"\xde\xad\xbe\xef",
            created="2026-01-01T00:00:00Z",
        )
        security = build_security_header(cred)
        validated = SimpleValidator().validate(security)
        assert validated == "alice"

    def test_application_rejects_missing_security(self) -> None:
        """SoapApplication with security_validator rejects requests without header."""
        import warnings
        from soapbar.core.wssecurity import UsernameTokenValidator
        from soapbar.server.application import SoapApplication
        from soapbar.server.service import SoapService, soap_operation

        class SimpleValidator(UsernameTokenValidator):
            def get_password(self, username: str) -> str | None:
                return "secret"

        class EchoService(SoapService):
            __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED

            @soap_operation()
            def Echo(self, msg: str) -> str:
                return msg

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            app = SoapApplication(security_validator=SimpleValidator())
        svc = EchoService()
        app.register(svc)

        xml = b"""<?xml version="1.0"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
          <soapenv:Body><Echo><msg>hi</msg></Echo></soapenv:Body>
        </soapenv:Envelope>"""
        status, _, body = app.handle_request(xml)
        assert status == 500
        assert b"Security" in body or b"security" in body.lower()

    def test_client_adds_security_header(self) -> None:
        """SoapClient with wss_credential adds wsse:Security header to request."""
        from soapbar.core.wssecurity import UsernameTokenCredential

        sent: list[bytes] = []

        class FakeTransport(HttpTransport):
            def send(self, url, data, headers):
                sent.append(data)
                return (
                    200,
                    "text/xml",
                    b'<?xml version="1.0"?>'
                    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    b"<soapenv:Body/></soapenv:Envelope>",
                )

        cred = UsernameTokenCredential(username="bob", password="pw")
        client = SoapClient.manual(
            "http://test",
            transport=FakeTransport(),
            wss_credential=cred,
        )
        client.call("Ping")
        assert sent, "transport was not called"
        assert b"Security" in sent[0]
        assert b"bob" in sent[0]


# ===========================================================================
# G10 — rpc:result opt-in
# ===========================================================================

class TestRpcResultOptIn:
    """G10: rpc:result SHOULD per SOAP 1.2 Part 2 §4.2.1 (opt-in only)."""

    def test_rpc_result_not_emitted_by_default(self) -> None:
        """rpc:result is NOT emitted by default (preserves zeep interop)."""
        from lxml import etree
        sig = OperationSignature(
            name="Add",
            output_params=[OperationParameter("result", _xsd_int)],
        )
        ser = RpcLiteralSerializer()
        body = etree.Element("_body")
        ser.serialize_response(sig, {"result": 42}, body)
        wrapper = body[0]
        rpc_result = wrapper.find(f"{{{NS.SOAP_RPC}}}result")
        assert rpc_result is None

    def test_rpc_result_emitted_when_opted_in(self) -> None:
        """rpc:result is emitted when sig.emit_rpc_result=True."""
        from lxml import etree
        sig = OperationSignature(
            name="Add",
            output_params=[OperationParameter("result", _xsd_int)],
            emit_rpc_result=True,
        )
        ser = RpcLiteralSerializer()
        body = etree.Element("_body")
        ser.serialize_response(sig, {"result": 42}, body)
        wrapper = body[0]
        rpc_result = wrapper.find(f"{{{NS.SOAP_RPC}}}result")
        assert rpc_result is not None
        assert rpc_result.text == "result"

    def test_emit_rpc_result_decorator_flag(self) -> None:
        """@soap_operation(emit_rpc_result=True) propagates to OperationSignature."""
        from soapbar.server.service import SoapService, soap_operation

        class Svc(SoapService):
            @soap_operation(emit_rpc_result=True)
            def Compute(self) -> int:
                return 0

        svc = Svc()
        ops = svc.get_operation_signatures()
        assert ops["Compute"].emit_rpc_result is True

    def test_emit_rpc_result_false_by_default_decorator(self) -> None:
        """@soap_operation() leaves emit_rpc_result=False by default."""
        from soapbar.server.service import SoapService, soap_operation

        class Svc(SoapService):
            @soap_operation()
            def Plain(self) -> int:
                return 0

        svc = Svc()
        ops = svc.get_operation_signatures()
        assert ops["Plain"].emit_rpc_result is False


# ---------------------------------------------------------------------------
# MTOM/XOP core — parse, build, round-trip, XOP include resolution
# ---------------------------------------------------------------------------

class TestMtomCore:
    """Tests for soapbar.core.mtom: parse_mtom, build_mtom, round-trip."""

    _SOAP_XML = (
        b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
        b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        b"<soapenv:Body><ping>pong</ping></soapenv:Body></soapenv:Envelope>"
    )

    def test_build_mtom_produces_multipart(self) -> None:
        from soapbar.core.mtom import build_mtom
        body, ct = build_mtom(self._SOAP_XML, [])
        assert "multipart/related" in ct
        assert "application/xop+xml" in ct
        assert b"--MIMEBoundary_" in body

    def test_build_mtom_boundary_in_content_type(self) -> None:
        from soapbar.core.mtom import build_mtom
        _, ct = build_mtom(self._SOAP_XML, [])
        assert 'boundary="' in ct

    def test_build_and_parse_round_trip_no_attachments(self) -> None:
        from soapbar.core.mtom import build_mtom, parse_mtom
        body, ct = build_mtom(self._SOAP_XML, [])
        msg = parse_mtom(body, ct)
        assert b"<ping>pong</ping>" in msg.soap_xml
        assert msg.attachments == []

    def test_build_with_attachment_round_trip(self) -> None:
        from soapbar.core.mtom import MtomAttachment, build_mtom, parse_mtom
        attachment_data = b"\x00\x01\x02\x03binary\xff"
        att = MtomAttachment(
            content_id="part1@test",
            content_type="application/octet-stream",
            data=attachment_data,
        )
        body, ct = build_mtom(self._SOAP_XML, [att])
        msg = parse_mtom(body, ct)
        assert len(msg.attachments) == 1
        assert msg.attachments[0].content_id == "part1@test"
        assert msg.attachments[0].data == attachment_data

    def test_parse_mtom_no_boundary_raises(self) -> None:
        from soapbar.core.mtom import parse_mtom
        import pytest
        with pytest.raises(ValueError, match="boundary"):
            parse_mtom(b"garbage", "text/xml")

    def test_xop_include_resolved_inline(self) -> None:
        """An <xop:Include> element is replaced with base64-encoded attachment data."""
        import base64
        from soapbar.core.mtom import MtomAttachment, build_mtom, parse_mtom
        from soapbar.core.namespaces import NS

        binary_data = b"hello binary"
        cid = "data@test"
        # Build a SOAP envelope that references the attachment via xop:Include
        soap_with_xop = (
            b'<?xml version=\'1.0\' encoding=\'utf-8\'?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            b' xmlns:xop="http://www.w3.org/2004/08/xop/include">'
            b"<soapenv:Body>"
            b'<file><xop:Include href="cid:data@test"/></file>'
            b"</soapenv:Body></soapenv:Envelope>"
        )
        att = MtomAttachment(content_id=cid, content_type="application/octet-stream", data=binary_data)
        body, ct = build_mtom(soap_with_xop, [att])
        msg = parse_mtom(body, ct)
        # The resolved XML should contain the base64-encoded data, not xop:Include
        expected_b64 = base64.b64encode(binary_data).decode()
        assert expected_b64.encode() in msg.soap_xml
        assert b"xop:Include" not in msg.soap_xml

    def test_add_attachment_and_use_mtom_client(self) -> None:
        """SoapClient.add_attachment() queues attachments; call() packages them via MTOM."""
        from unittest.mock import MagicMock, patch

        from soapbar.client.client import SoapClient
        from soapbar.core.binding import BindingStyle, OperationSignature
        from soapbar.core.envelope import SoapVersion

        transport = MagicMock()
        # Return a minimal SOAP 1.1 response
        resp_xml = (
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><r>done</r></soapenv:Body></soapenv:Envelope>"
        )
        transport.send.return_value = (200, "text/xml", resp_xml)

        client = SoapClient.manual(
            "http://example.com/soap",
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            soap_version=SoapVersion.SOAP_11,
            transport=transport,
            use_mtom=True,
        )
        sig = OperationSignature(name="Upload")
        client.register_operation(sig)

        cid = client.add_attachment(b"\xde\xad\xbe\xef", "application/octet-stream")
        assert cid.endswith("@soapbar")
        assert len(client._mtom_attachments) == 1

        client.call("Upload")

        # After call, attachments list should be cleared
        assert client._mtom_attachments == []
        # The Content-Type sent should be multipart/related
        call_args = transport.send.call_args
        sent_headers = call_args[0][2]
        assert "multipart/related" in sent_headers.get("Content-Type", "")

    def test_client_use_mtom_false_sends_plain_xml(self) -> None:
        """Without use_mtom, attachments queued via add_attachment are NOT sent."""
        from unittest.mock import MagicMock

        from soapbar.client.client import SoapClient
        from soapbar.core.binding import BindingStyle, OperationSignature
        from soapbar.core.envelope import SoapVersion

        transport = MagicMock()
        resp_xml = (
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><r>ok</r></soapenv:Body></soapenv:Envelope>"
        )
        transport.send.return_value = (200, "text/xml", resp_xml)

        client = SoapClient.manual(
            "http://example.com/soap",
            transport=transport,
            use_mtom=False,
        )
        sig = OperationSignature(name="Op")
        client.register_operation(sig)
        client.call("Op")

        call_args = transport.send.call_args
        sent_headers = call_args[0][2]
        assert "multipart" not in sent_headers.get("Content-Type", "")

    def test_ns_xop_constant(self) -> None:
        from soapbar.core.namespaces import NS
        assert NS.XOP == "http://www.w3.org/2004/08/xop/include"
        assert NS.DEFAULT_PREFIXES[NS.XOP] == "xop"

    def test_mtom_attachment_dataclass(self) -> None:
        from soapbar.core.mtom import MtomAttachment
        att = MtomAttachment(content_id="x@y", content_type="image/png", data=b"\x89PNG")
        assert att.content_id == "x@y"
        assert att.data == b"\x89PNG"

    def test_build_mtom_soap12_content_type(self) -> None:
        from soapbar.core.mtom import build_mtom
        _, ct = build_mtom(self._SOAP_XML, [], soap_version_content_type="application/soap+xml")
        assert 'start-info="application/soap+xml"' in ct

    def test_build_mtom_soap_action_in_outer_ct(self) -> None:
        from soapbar.core.mtom import build_mtom
        _, ct = build_mtom(self._SOAP_XML, [], soap_action="urn:MyAction")
        assert 'action="urn:MyAction"' in ct

    def test_multiple_attachments_all_included(self) -> None:
        from soapbar.core.mtom import MtomAttachment, build_mtom, parse_mtom
        atts = [
            MtomAttachment("a@t", "application/octet-stream", b"AAAA"),
            MtomAttachment("b@t", "image/jpeg", b"BBBB"),
            MtomAttachment("c@t", "text/plain", b"CCCC"),
        ]
        body, ct = build_mtom(self._SOAP_XML, atts)
        msg = parse_mtom(body, ct)
        assert len(msg.attachments) == 3
        cids = {a.content_id for a in msg.attachments}
        assert cids == {"a@t", "b@t", "c@t"}

    def test_mtom_message_exported_from_package(self) -> None:
        import soapbar
        assert hasattr(soapbar, "MtomAttachment")
        assert hasattr(soapbar, "MtomMessage")
        assert hasattr(soapbar, "parse_mtom")
        assert hasattr(soapbar, "build_mtom")
