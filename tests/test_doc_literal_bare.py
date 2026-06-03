"""Document/literal *bare* + xsd:any passthrough (Finding A).

When an operation's single body part references a global element whose content
model is an ``xsd:any`` wildcard (e.g. SEFAZ NF-e's ``nfeDadosMsg``), the body
*is* that element and carries raw XML verbatim — not an operation-named wrapper
with child accessors. The caller's XML must reach the wire unchanged, and the
response's inner XML must come back as a string.
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport
from soapbar.core.binding import BindingStyle
from soapbar.core.types import AnyXmlType

WSDL_NS = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4"
NFE_NS = "http://www.portalfiscal.inf.br/nfe"

_WSDL = f"""<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:tns="{WSDL_NS}" targetNamespace="{WSDL_NS}">
  <wsdl:types><xsd:schema targetNamespace="{WSDL_NS}" elementFormDefault="qualified">
    <xsd:element name="nfeDadosMsg"><xsd:complexType><xsd:sequence>
      <xsd:any processContents="skip"/></xsd:sequence></xsd:complexType></xsd:element>
    <xsd:element name="nfeResultMsg"><xsd:complexType><xsd:sequence>
      <xsd:any processContents="skip"/></xsd:sequence></xsd:complexType></xsd:element>
  </xsd:schema></wsdl:types>
  <wsdl:message name="Req"><wsdl:part name="nfeDadosMsg" element="tns:nfeDadosMsg"/></wsdl:message>
  <wsdl:message name="Res">
    <wsdl:part name="nfeResultMsg" element="tns:nfeResultMsg"/></wsdl:message>
  <wsdl:portType name="PT"><wsdl:operation name="nfeStatusServicoNF">
    <wsdl:input message="tns:Req"/><wsdl:output message="tns:Res"/></wsdl:operation></wsdl:portType>
  <wsdl:binding name="B" type="tns:PT">
    <soap12:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="nfeStatusServicoNF">
      <soap12:operation soapAction="{WSDL_NS}/nfeStatusServicoNF"/>
      <wsdl:input><soap12:body use="literal"/></wsdl:input>
      <wsdl:output><soap12:body use="literal"/></wsdl:output></wsdl:operation></wsdl:binding>
  <wsdl:service name="S"><wsdl:port name="P" binding="tns:B">
    <soap12:address location="https://ex.invalid/ws"/></wsdl:port></wsdl:service>
</wsdl:definitions>"""

_RET = (
    f'<retConsStatServ xmlns="{NFE_NS}" versao="4.00">'
    "<tpAmb>2</tpAmb><cStat>107</cStat><xMotivo>Servico em Operacao</xMotivo></retConsStatServ>"
)
_CONS = (
    f'<consStatServ xmlns="{NFE_NS}" versao="4.00">'
    "<tpAmb>2</tpAmb><cUF>31</cUF><xServ>STATUS</xServ></consStatServ>"
)


class _CaptureTransport(HttpTransport):
    def __init__(self) -> None:
        super().__init__()
        self.body: bytes | None = None

    def send(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, bytes]:
        self.body = body
        env = (
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>'
            f'<nfeResultMsg xmlns="{WSDL_NS}">{_RET}</nfeResultMsg></soap:Body></soap:Envelope>'
        )
        return 200, "application/soap+xml", env.encode()


def _client() -> tuple[SoapClient, _CaptureTransport]:
    client = SoapClient.from_wsdl_string(_WSDL)
    transport = _CaptureTransport()
    client._transport = transport
    return client, transport


def test_bare_operation_is_not_wrapped() -> None:
    client, _ = _client()
    assert client._binding_style is BindingStyle.DOCUMENT_LITERAL
    params = client._signatures["nfeStatusServicoNF"].input_params
    assert len(params) == 1
    assert params[0].name == "nfeDadosMsg"
    assert isinstance(params[0].xsd_type, AnyXmlType)
    assert params[0].namespace == WSDL_NS


def test_request_carries_raw_payload_in_body_element() -> None:
    client, transport = _client()
    client.call("nfeStatusServicoNF", nfeDadosMsg=_CONS)
    assert transport.body is not None
    body = transport.body.decode()
    # The body element is <nfeDadosMsg> (in the WSDL ns), not an operation wrapper.
    assert "nfeStatusServicoNF" not in body  # no operation-named wrapper
    assert "nfeDadosMsg" in body
    assert WSDL_NS in body
    # The caller's payload is grafted in verbatim.
    assert "<consStatServ" in body
    assert "<xServ>STATUS</xServ>" in body


def test_response_inner_xml_returned_as_string() -> None:
    client, _ = _client()
    result = client.call("nfeStatusServicoNF", nfeDadosMsg=_CONS)
    assert isinstance(result, str)
    assert "retConsStatServ" in result
    assert "<cStat>107</cStat>" in result


def test_wildcard_detection_distinguishes_named_elements() -> None:
    client, _ = _client()
    assert client._element_is_any_wildcard("nfeDadosMsg") is True
    assert client._element_is_any_wildcard("does-not-exist") is False


def test_anyxml_type_value_conversions() -> None:
    t = AnyXmlType()
    assert t.to_xml("<x/>") == "<x/>"
    assert t.to_xml(b"<x/>") == "<x/>"  # bytes are decoded
    assert t.from_xml("<x/>") == "<x/>"


def test_empty_bare_payload_emits_empty_element() -> None:
    client, transport = _client()
    client.call("nfeStatusServicoNF", nfeDadosMsg="")
    assert transport.body is not None
    assert b"nfeDadosMsg" in transport.body  # carrier present, no grafted child
