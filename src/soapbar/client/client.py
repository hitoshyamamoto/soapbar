"""SOAP client."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from soapbar.client.transport import HttpTransport
from soapbar.core.binding import BindingStyle, OperationSignature, get_serializer
from soapbar.core.envelope import SoapEnvelope, SoapVersion, http_headers
from soapbar.core.namespaces import NS
from soapbar.core.wsdl import WsdlDefinition
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file


class _ServiceProxy:
    def __init__(self, client: SoapClient) -> None:
        self._client = client

    def __getattr__(self, name: str) -> Any:
        def caller(**kwargs: Any) -> Any:
            return self._client.call(name, **kwargs)
        return caller


class SoapClient:
    def __init__(
        self,
        wsdl_url: str | None = None,
        transport: HttpTransport | None = None,
    ) -> None:
        self._transport = transport or HttpTransport()
        self._wsdl: WsdlDefinition | None = None
        self._address: str = ""
        self._binding_style: BindingStyle = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        self._soap_version: SoapVersion = SoapVersion.SOAP_11
        self._signatures: dict[str, OperationSignature] = {}

        if wsdl_url is not None:
            wsdl_bytes = self._transport.fetch(wsdl_url)
            self._init_from_wsdl(parse_wsdl(wsdl_bytes))

        self.service = _ServiceProxy(self)

    def _init_from_wsdl(self, defn: WsdlDefinition) -> None:
        self._wsdl = defn
        self._address = defn.first_service_address or ""
        binding = defn.first_binding
        if binding:
            self._binding_style = binding.binding_style_for(
                binding.operations[0].name if binding.operations else ""
            )
            if binding.soap_ns == NS.WSDL_SOAP12:
                self._soap_version = SoapVersion.SOAP_12

    @classmethod
    def from_file(cls, path: str | Path) -> SoapClient:
        obj: SoapClient = cls.__new__(cls)
        obj._transport = HttpTransport()
        obj._wsdl = None
        obj._address = ""
        obj._binding_style = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        obj._soap_version = SoapVersion.SOAP_11
        obj._signatures = {}
        obj.service = _ServiceProxy(obj)
        defn = parse_wsdl_file(path)
        obj._init_from_wsdl(defn)
        return obj

    @classmethod
    def from_wsdl_string(cls, wsdl: str | bytes) -> SoapClient:
        obj: SoapClient = cls.__new__(cls)
        obj._transport = HttpTransport()
        obj._wsdl = None
        obj._address = ""
        obj._binding_style = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        obj._soap_version = SoapVersion.SOAP_11
        obj._signatures = {}
        obj.service = _ServiceProxy(obj)
        defn = parse_wsdl(wsdl)
        obj._init_from_wsdl(defn)
        return obj

    @classmethod
    def manual(
        cls,
        address: str,
        binding_style: BindingStyle = BindingStyle.DOCUMENT_LITERAL_WRAPPED,
        soap_version: SoapVersion = SoapVersion.SOAP_11,
        transport: HttpTransport | None = None,
    ) -> SoapClient:
        obj: SoapClient = cls.__new__(cls)
        obj._transport = transport or HttpTransport()
        obj._wsdl = None
        obj._address = address
        obj._binding_style = binding_style
        obj._soap_version = soap_version
        obj._signatures = {}
        obj.service = _ServiceProxy(obj)
        return obj

    def register_operation(self, sig: OperationSignature) -> None:
        self._signatures[sig.name] = sig

    def call(self, operation: str, **kwargs: Any) -> Any:
        sig = self._get_sig(operation)
        serializer = get_serializer(self._binding_style)

        envelope = SoapEnvelope(version=self._soap_version)

        from lxml import etree
        body_container = etree.Element("_body")
        serializer.serialize_request(sig, kwargs, body_container)
        for child in body_container:
            envelope.add_body_content(child)

        req_bytes = envelope.to_bytes()
        headers = http_headers(self._soap_version, sig.soap_action)
        headers["Content-Type"] = headers.get("Content-Type", self._soap_version.content_type)

        status, _ct, resp_body = self._transport.send(self._address, req_bytes, headers)
        return self._parse_response(sig, resp_body, status)

    async def call_async(self, operation: str, **kwargs: Any) -> Any:
        sig = self._get_sig(operation)
        serializer = get_serializer(self._binding_style)

        envelope = SoapEnvelope(version=self._soap_version)

        from lxml import etree
        body_container = etree.Element("_body")
        serializer.serialize_request(sig, kwargs, body_container)
        for child in body_container:
            envelope.add_body_content(child)

        req_bytes = envelope.to_bytes()
        headers = http_headers(self._soap_version, sig.soap_action)

        status, _ct, resp_body = await self._transport.send_async(self._address, req_bytes, headers)
        return self._parse_response(sig, resp_body, status)

    def _get_sig(self, operation: str) -> OperationSignature:
        if operation in self._signatures:
            return self._signatures[operation]
        # Build minimal signature
        return OperationSignature(name=operation)

    def _parse_response(
        self,
        sig: OperationSignature,
        resp_body: bytes,
        status: int,
    ) -> Any:
        envelope = SoapEnvelope.from_xml(resp_body)
        if envelope.is_fault:
            fault = envelope.fault
            raise fault  # type: ignore[misc]

        body_elem = envelope.first_body_element
        if body_elem is None:
            return None

        serializer = get_serializer(self._binding_style)
        from lxml import etree
        container = etree.Element("_body")
        container.append(body_elem)
        values = serializer.deserialize_response(sig, container)

        if len(values) == 1:
            return next(iter(values.values()))
        return values if values else None
