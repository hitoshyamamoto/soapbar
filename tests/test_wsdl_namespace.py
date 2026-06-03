"""Regression tests: document/literal body-wrapper namespace resolution.

When a WSDL declares its message elements in a *schema* namespace different
from the WSDL targetNamespace (the common real-world case — e.g. EU VIES uses
`…:checkVat:types`), the parser must resolve the part's element to that schema
namespace and the client must qualify the request wrapper with it. Previously
`input_namespace` came back None and soapbar emitted an unqualified wrapper,
which strict servers reject.
"""
from __future__ import annotations

from pathlib import Path

from soapbar import parse_wsdl
from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport

# Minimal document/literal WSDL whose element lives in a *separate* schema
# namespace (urn:ex:types) from the WSDL targetNamespace (urn:ex:svc).
_WSDL = b"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:tns="urn:ex:svc" xmlns:t="urn:ex:types"
    targetNamespace="urn:ex:svc">
  <types>
    <xsd:schema targetNamespace="urn:ex:types" elementFormDefault="qualified">
      <xsd:element name="Ping">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="msg" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </types>
  <message name="PingReq"><part name="parameters" element="t:Ping"/></message>
  <portType name="PT"><operation name="Ping"><input message="tns:PingReq"/></operation></portType>
  <binding name="B" type="tns:PT">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Ping"><soap:operation soapAction=""/>
      <input><soap:body use="literal"/></input>
    </operation>
  </binding>
  <service name="S"><port name="P" binding="tns:B">
    <soap:address location="http://example.invalid/svc"/>
  </port></service>
</definitions>
"""


def test_parser_resolves_part_element_namespace() -> None:
    defn = parse_wsdl(_WSDL)
    part = defn.messages["PingReq"].parts[0]
    # The schema namespace, not the WSDL targetNamespace.
    assert part.element_ns == "urn:ex:types"


def test_client_qualifies_doc_literal_wrapper(tmp_path: Path) -> None:
    path = tmp_path / "svc.wsdl"
    path.write_bytes(_WSDL)
    client = SoapClient.from_file(str(path))
    assert client._signatures["Ping"].input_namespace == "urn:ex:types"


def test_from_file_accepts_transport_and_endpoint(tmp_path: Path) -> None:
    path = tmp_path / "svc.wsdl"
    path.write_bytes(_WSDL)
    transport = HttpTransport(timeout=5)
    client = SoapClient.from_file(
        str(path), transport=transport, endpoint="https://override.invalid/svc"
    )
    assert client._transport is transport  # injected, not a fresh default
    assert client._address == "https://override.invalid/svc"  # overrides the WSDL address
