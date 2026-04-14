# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""SOAP client."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from soapbar.client.transport import HttpTransport
from soapbar.core.binding import BindingStyle, OperationSignature, get_serializer
from soapbar.core.envelope import SoapEnvelope, SoapVersion, http_headers
from soapbar.core.namespaces import NS
from soapbar.core.wsdl import WsdlDefinition
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file
from soapbar.core.xml import make_element


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
        use_wsa: bool = False,
        wss_credential: Any = None,
        use_mtom: bool = False,
    ) -> None:
        self._transport = transport or HttpTransport()
        self._wsdl: WsdlDefinition | None = None
        self._address: str = ""
        self._binding_style: BindingStyle = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        self._soap_version: SoapVersion = SoapVersion.SOAP_11
        self._signatures: dict[str, OperationSignature] = {}
        self._use_wsa: bool = use_wsa
        self._wss_credential = wss_credential  # G09: UsernameTokenCredential or None
        self._use_mtom: bool = use_mtom
        self._mtom_attachments: list[Any] = []  # MtomAttachment items to send

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
    def from_file(cls, path: str | Path, use_wsa: bool = False) -> SoapClient:
        obj: SoapClient = cls.__new__(cls)
        obj._transport = HttpTransport()
        obj._wsdl = None
        obj._address = ""
        obj._binding_style = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        obj._soap_version = SoapVersion.SOAP_11
        obj._signatures = {}
        obj._use_wsa = use_wsa
        obj._wss_credential = None
        obj._use_mtom = False
        obj._mtom_attachments = []
        obj.service = _ServiceProxy(obj)
        defn = parse_wsdl_file(path)
        obj._init_from_wsdl(defn)
        return obj

    @classmethod
    def from_wsdl_string(cls, wsdl: str | bytes, use_wsa: bool = False) -> SoapClient:
        obj: SoapClient = cls.__new__(cls)
        obj._transport = HttpTransport()
        obj._wsdl = None
        obj._address = ""
        obj._binding_style = BindingStyle.DOCUMENT_LITERAL_WRAPPED
        obj._soap_version = SoapVersion.SOAP_11
        obj._signatures = {}
        obj._use_wsa = use_wsa
        obj._wss_credential = None
        obj._use_mtom = False
        obj._mtom_attachments = []
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
        use_wsa: bool = False,
        wss_credential: Any = None,
        use_mtom: bool = False,
    ) -> SoapClient:
        obj: SoapClient = cls.__new__(cls)
        obj._transport = transport or HttpTransport()
        obj._wsdl = None
        obj._address = address
        obj._binding_style = binding_style
        obj._soap_version = soap_version
        obj._signatures = {}
        obj._use_wsa = use_wsa
        obj._wss_credential = wss_credential
        obj._use_mtom = use_mtom
        obj._mtom_attachments = []
        obj.service = _ServiceProxy(obj)
        return obj

    def register_operation(self, sig: OperationSignature) -> None:
        self._signatures[sig.name] = sig

    def close(self) -> None:
        """Close the underlying transport's pooled HTTP client, if any.

        Safe to call multiple times. Since 0.6.1 :class:`HttpTransport`
        maintains a long-lived ``httpx.Client`` for connection reuse;
        calling ``close()`` releases that client and the connections it
        owns. Not required for correctness (the transport tolerates
        garbage-collection), but recommended in long-running processes
        that create many short-lived ``SoapClient`` instances.
        """
        close = getattr(self._transport, "close", None)
        if callable(close):
            close()

    async def aclose(self) -> None:
        """Async counterpart to :meth:`close` for the async transport."""
        aclose = getattr(self._transport, "aclose", None)
        if callable(aclose):
            await aclose()

    def __enter__(self) -> SoapClient:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def add_attachment(self, data: bytes, content_type: str, content_id: str | None = None) -> str:
        """Queue a binary attachment to be sent with the next MTOM call.

        Returns the Content-ID (without angle brackets) that can be used in
        an ``<xop:Include href="cid:…"/>`` element inside the SOAP body.
        Only meaningful when ``use_mtom=True``.
        """
        from soapbar.core.mtom import MtomAttachment
        cid = content_id or f"{uuid.uuid4()}@soapbar"
        self._mtom_attachments.append(
            MtomAttachment(content_id=cid, content_type=content_type, data=data)
        )
        return cid

    def _build_wsa_headers(self, sig: OperationSignature) -> list[Any]:
        """Return WS-Addressing request header elements for *sig* when use_wsa is True."""
        wsa_ns = NS.WSA
        nsmap: dict[str | None, str] = {"wsa": wsa_ns}

        msg_id = make_element(f"{{{wsa_ns}}}MessageID", nsmap=nsmap)
        msg_id.text = f"urn:uuid:{uuid.uuid4()}"

        action_uri = sig.soap_action or sig.name
        action = make_element(f"{{{wsa_ns}}}Action", nsmap=nsmap)
        action.text = action_uri

        return [msg_id, action]

    def call(self, operation: str, **kwargs: Any) -> Any:
        sig = self._get_sig(operation)
        serializer = get_serializer(self._binding_style, self._soap_version)

        envelope = SoapEnvelope(version=self._soap_version)

        # G09: inject WS-Security header before other headers
        if self._wss_credential is not None:
            from soapbar.core.wssecurity import build_security_header
            envelope.add_header(build_security_header(
                self._wss_credential,
                soap_ns=self._soap_version.envelope_ns,
            ))

        if self._use_wsa:
            for hdr in self._build_wsa_headers(sig):
                envelope.add_header(hdr)

        from lxml import etree
        body_container = etree.Element("_body")
        serializer.serialize_request(sig, kwargs, body_container)
        for child in body_container:
            envelope.add_body_content(child)

        req_bytes = envelope.to_bytes()
        headers = http_headers(self._soap_version, sig.soap_action)
        headers["Content-Type"] = headers.get("Content-Type", self._soap_version.content_type)

        if self._use_mtom and self._mtom_attachments:
            from soapbar.core.mtom import build_mtom
            attachments = list(self._mtom_attachments)
            self._mtom_attachments.clear()
            req_bytes, headers["Content-Type"] = build_mtom(
                req_bytes,
                attachments,
                soap_version_content_type=self._soap_version.content_type,
                soap_action=sig.soap_action or "",
            )

        status, _ct, resp_body = self._transport.send(self._address, req_bytes, headers)
        return self._parse_response(sig, resp_body, status)

    async def call_async(self, operation: str, **kwargs: Any) -> Any:
        sig = self._get_sig(operation)
        serializer = get_serializer(self._binding_style, self._soap_version)

        envelope = SoapEnvelope(version=self._soap_version)

        # G09: inject WS-Security header before other headers (mirrors call())
        if self._wss_credential is not None:
            from soapbar.core.wssecurity import build_security_header
            envelope.add_header(build_security_header(
                self._wss_credential,
                soap_ns=self._soap_version.envelope_ns,
            ))

        if self._use_wsa:
            for hdr in self._build_wsa_headers(sig):
                envelope.add_header(hdr)

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

        serializer = get_serializer(self._binding_style, self._soap_version)
        from lxml import etree
        container = etree.Element("_body")
        container.append(body_elem)
        values = serializer.deserialize_response(sig, container)

        if len(values) == 1:
            return next(iter(values.values()))
        return values if values else None
