"""SOAP Envelope builder and parser."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.xml import (
    local_name,
    make_element,
    namespace_uri,
    parse_xml_document,
    sub_element,
    to_bytes,
    to_string,
)

# ---------------------------------------------------------------------------
# SOAP Header Block
# ---------------------------------------------------------------------------

@dataclass
class SoapHeaderBlock:
    """A single SOAP header block with parsed attributes."""
    element: _Element
    must_understand: bool = False
    relay: bool = False        # SOAP 1.2 only
    role: str | None = None    # SOAP 1.2 role / SOAP 1.1 actor


# ---------------------------------------------------------------------------
# WS-Addressing dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WsaEndpointReference:
    """WS-Addressing endpoint reference."""
    address: str
    reference_parameters: list[_Element] = field(default_factory=list)


@dataclass
class WsaHeaders:
    """Parsed WS-Addressing headers from a SOAP envelope."""
    message_id: str | None = None
    to: str | None = None
    action: str | None = None
    from_: WsaEndpointReference | None = None
    reply_to: WsaEndpointReference | None = None
    fault_to: WsaEndpointReference | None = None
    relates_to: str | None = None
    relates_to_relationship: str = "http://www.w3.org/2005/08/addressing/reply"


def _parse_endpoint_reference(elem: _Element) -> WsaEndpointReference:
    """Parse a wsa:EndpointReference element."""
    addr_elem = elem.find(f"{{{NS.WSA}}}Address")
    address = addr_elem.text or "" if addr_elem is not None else ""
    rp_elem = elem.find(f"{{{NS.WSA}}}ReferenceParameters")
    ref_params = list(rp_elem) if rp_elem is not None else []
    return WsaEndpointReference(address=address, reference_parameters=ref_params)


def _parse_ws_addressing(header_blocks: list[SoapHeaderBlock]) -> WsaHeaders | None:
    """Scan header blocks for WS-Addressing elements and build WsaHeaders."""
    wsa_ns = NS.WSA
    found_any = False
    wsa = WsaHeaders()
    for block in header_blocks:
        elem = block.element
        if namespace_uri(elem) != wsa_ns:
            continue
        found_any = True
        lname = local_name(elem)
        if lname == "MessageID":
            wsa.message_id = elem.text
        elif lname == "To":
            wsa.to = elem.text
        elif lname == "Action":
            wsa.action = elem.text
        elif lname == "ReplyTo":
            wsa.reply_to = _parse_endpoint_reference(elem)
        elif lname == "From":
            wsa.from_ = _parse_endpoint_reference(elem)
        elif lname == "FaultTo":
            wsa.fault_to = _parse_endpoint_reference(elem)
        elif lname == "RelatesTo":
            wsa.relates_to = elem.text
            rel = elem.get(f"{{{wsa_ns}}}RelationshipType") or elem.get("RelationshipType")
            if rel:
                wsa.relates_to_relationship = rel
    return wsa if found_any else None


class SoapVersion(Enum):
    SOAP_11 = "1.1"
    SOAP_12 = "1.2"

    @property
    def envelope_ns(self) -> str:
        return NS.SOAP_ENV if self == SoapVersion.SOAP_11 else NS.SOAP12_ENV

    @property
    def encoding_ns(self) -> str:
        return NS.SOAP_ENC if self == SoapVersion.SOAP_11 else NS.SOAP12_ENC

    @property
    def content_type(self) -> str:
        if self == SoapVersion.SOAP_11:
            return "text/xml; charset=utf-8"
        return "application/soap+xml; charset=utf-8"

    @property
    def prefix(self) -> str:
        return "soapenv" if self == SoapVersion.SOAP_11 else "soap12"


@dataclass(init=False)
class SoapEnvelope:
    version: SoapVersion
    header_blocks: list[SoapHeaderBlock]
    body_elements: list[_Element]
    ws_addressing: WsaHeaders | None
    ws_security_element: _Element | None

    def __init__(
        self,
        version: SoapVersion = SoapVersion.SOAP_11,
        header_blocks: list[SoapHeaderBlock] | None = None,
        body_elements: list[_Element] | None = None,
        ws_addressing: WsaHeaders | None = None,
        ws_security_element: _Element | None = None,
        header_elements: list[_Element] | None = None,
    ) -> None:
        self.version = version
        self.header_blocks = header_blocks if header_blocks is not None else []
        self.body_elements = body_elements if body_elements is not None else []
        self.ws_addressing = ws_addressing
        self.ws_security_element = ws_security_element
        if header_elements is not None:
            self.header_blocks = [SoapHeaderBlock(element=e) for e in header_elements]

    @property
    def header_elements(self) -> list[_Element]:
        return [b.element for b in self.header_blocks]

    @header_elements.setter
    def header_elements(self, elems: list[_Element]) -> None:
        self.header_blocks = [SoapHeaderBlock(element=e) for e in elems]

    def add_header(self, elem: _Element | SoapHeaderBlock) -> None:
        if isinstance(elem, SoapHeaderBlock):
            self.header_blocks.append(elem)
        else:
            self.header_blocks.append(SoapHeaderBlock(element=elem))

    def add_body_content(self, elem: _Element) -> None:
        self.body_elements.append(elem)

    def build(self) -> _Element:
        env_ns = self.version.envelope_ns
        prefix = self.version.prefix
        nsmap: dict[str | None, str] = {prefix: env_ns}

        env = make_element(f"{{{env_ns}}}Envelope", nsmap=nsmap)

        if self.header_blocks:
            header = sub_element(env, f"{{{env_ns}}}Header")
            for block in self.header_blocks:
                header.append(block.element)

        body = sub_element(env, f"{{{env_ns}}}Body")
        for elem in self.body_elements:
            body.append(elem)

        return env

    def to_string(self, pretty_print: bool = False) -> str:
        return to_string(self.build(), pretty_print=pretty_print)

    def to_bytes(self, pretty_print: bool = False) -> bytes:
        return to_bytes(self.build(), pretty_print=pretty_print)

    @classmethod
    def from_xml(cls, source: str | bytes | _Element) -> SoapEnvelope:
        root = parse_xml_document(source)
        ns = namespace_uri(root)

        if ns == NS.SOAP_ENV:
            version = SoapVersion.SOAP_11
        elif ns == NS.SOAP12_ENV:
            version = SoapVersion.SOAP_12
        else:
            raise ValueError(f"Unknown SOAP envelope namespace: {ns!r}")

        env_ns = version.envelope_ns
        header_blocks: list[SoapHeaderBlock] = []
        body_elements: list[_Element] = []

        header_elem = root.find(f"{{{env_ns}}}Header")
        if header_elem is not None:
            for hdr in list(header_elem):
                mu_val = hdr.get(f"{{{env_ns}}}mustUnderstand") or hdr.get("mustUnderstand", "0")
                mu = mu_val in ("1", "true")
                relay_val = hdr.get(f"{{{env_ns}}}relay", "false")
                relay = relay_val in ("1", "true")
                role = hdr.get(f"{{{env_ns}}}role") or hdr.get(f"{{{env_ns}}}actor")
                header_blocks.append(SoapHeaderBlock(
                    element=hdr, must_understand=mu, relay=relay, role=role,
                ))

        body_elem = root.find(f"{{{env_ns}}}Body")
        if body_elem is not None:
            body_elements = list(body_elem)

        envelope = cls(version=version)
        envelope.header_blocks = header_blocks
        envelope.body_elements = body_elements

        # Parse WS-Addressing
        envelope.ws_addressing = _parse_ws_addressing(header_blocks)

        # Detect WS-Security
        wsse_ns = NS.WSSE
        envelope.ws_security_element = next(
            (b.element for b in header_blocks
             if namespace_uri(b.element) == wsse_ns and local_name(b.element) == "Security"),
            None,
        )

        return envelope

    @property
    def is_fault(self) -> bool:
        if not self.body_elements:
            return False
        first = self.body_elements[0]
        return local_name(first) == "Fault"

    @property
    def fault(self) -> Any | None:
        if not self.is_fault:
            return None
        from soapbar.core.fault import SoapFault
        return SoapFault.from_element(self.body_elements[0])

    @property
    def first_body_element(self) -> _Element | None:
        return self.body_elements[0] if self.body_elements else None

    @property
    def operation_name(self) -> str | None:
        elem = self.first_body_element
        if elem is None:
            return None
        return local_name(elem)

    @property
    def operation_namespace(self) -> str | None:
        elem = self.first_body_element
        if elem is None:
            return None
        return namespace_uri(elem)


# ---------------------------------------------------------------------------
# Module-level one-shot constructors
# ---------------------------------------------------------------------------

def build_request(
    version: SoapVersion,
    body_elements: list[_Element],
    header_elements: list[_Element] | None = None,
) -> _Element:
    env = SoapEnvelope(version=version)
    for elem in (header_elements or []):
        env.add_header(elem)
    for elem in body_elements:
        env.add_body_content(elem)
    return env.build()


def build_response(
    version: SoapVersion,
    body_elements: list[_Element],
    header_elements: list[_Element] | None = None,
) -> _Element:
    return build_request(version, body_elements, header_elements)


def build_fault(
    version: SoapVersion,
    faultcode: str,
    faultstring: str,
    faultactor: str | None = None,
    detail: str | _Element | None = None,
) -> _Element:
    from soapbar.core.fault import SoapFault
    fault = SoapFault(faultcode, faultstring, faultactor=faultactor, detail=detail)
    if version == SoapVersion.SOAP_11:
        return fault.to_soap11_envelope()
    return fault.to_soap12_envelope()


def http_headers(
    version: SoapVersion,
    soap_action: str = "",
) -> dict[str, str]:
    headers = {"Content-Type": version.content_type}
    if version == SoapVersion.SOAP_11:
        headers["SOAPAction"] = f'"{soap_action}"'
    else:
        # SOAP 1.2: action= in Content-Type
        headers["Content-Type"] += f'; action="{soap_action}"'
    return headers
