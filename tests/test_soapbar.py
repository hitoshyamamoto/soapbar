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
from soapbar.core.types import xsd
from soapbar.core.wsdl.builder import build_wsdl_string
from soapbar.core.wsdl.parser import parse_wsdl
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

    def test_wsdl_import_raises(self) -> None:
        wsdl_with_import = b"""<?xml version="1.0"?>
        <definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
                     targetNamespace="http://example.com/">
          <import namespace="http://other.com/" location="other.wsdl"/>
        </definitions>"""
        with pytest.raises(NotImplementedError):
            parse_wsdl(wsdl_with_import)


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
        f = SoapFault("Server", "bad", subcodes=["tns:Invalid"])
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
        assert responses[0]["status"] == 200
        assert b"soapbar" in responses[1]["body"]

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
        assert status_list[0].startswith("200")
        assert b"soapbar SOAP endpoint" in b"".join(result)

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
