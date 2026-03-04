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


@dataclass
class SoapEnvelope:
    version: SoapVersion = SoapVersion.SOAP_11
    header_elements: list[_Element] = field(default_factory=list)
    body_elements: list[_Element] = field(default_factory=list)

    def add_header(self, elem: _Element) -> None:
        self.header_elements.append(elem)

    def add_body_content(self, elem: _Element) -> None:
        self.body_elements.append(elem)

    def build(self) -> _Element:
        env_ns = self.version.envelope_ns
        prefix = self.version.prefix
        nsmap: dict[str | None, str] = {prefix: env_ns}

        env = make_element(f"{{{env_ns}}}Envelope", nsmap=nsmap)

        if self.header_elements:
            header = sub_element(env, f"{{{env_ns}}}Header")
            for elem in self.header_elements:
                header.append(elem)

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
        header_elements: list[_Element] = []
        body_elements: list[_Element] = []

        header_elem = root.find(f"{{{env_ns}}}Header")
        if header_elem is not None:
            header_elements = list(header_elem)

        body_elem = root.find(f"{{{env_ns}}}Body")
        if body_elem is not None:
            body_elements = list(body_elem)

        envelope = cls(version=version)
        envelope.header_elements = header_elements
        envelope.body_elements = body_elements
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
