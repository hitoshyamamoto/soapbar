# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""SOAP client."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from soapbar.client.transport import HttpTransport
from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import SoapEnvelope, SoapVersion, http_headers
from soapbar.core.namespaces import NS
from soapbar.core.wsdl import (
    WsdlDefinition,
    WsdlOperation,
    WsdlOperationMessage,
)
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
        if binding is None:
            return

        self._binding_style = binding.binding_style_for(
            binding.operations[0].name if binding.operations else ""
        )
        if binding.soap_ns == NS.WSDL_SOAP12:
            self._soap_version = SoapVersion.SOAP_12

        # Upgrade DOCUMENT_LITERAL → DOCUMENT_LITERAL_WRAPPED when every
        # operation's input/output message matches the WS-I BP 1.1 DLW
        # shape (one part, part.element set, element local-name equals
        # the operation name). binding_style_for() can't distinguish DLW
        # from plain doc/literal via WSDL metadata alone; the message
        # shape is the spec-sanctioned signal.
        if (
            self._binding_style is BindingStyle.DOCUMENT_LITERAL
            and binding.operations
            and self._binding_is_dlw_shaped(defn, binding.operations)
        ):
            self._binding_style = BindingStyle.DOCUMENT_LITERAL_WRAPPED

        # Register one OperationSignature per binding operation so
        # client.call("Op", **kwargs) actually drives the call. Before
        # 0.6.3 this loop did not exist and the signature map stayed
        # empty, silently dropping kwargs. Missing / unresolvable
        # messages are skipped with a warning so partial WSDLs remain
        # parseable (same tolerance as parse_wsdl(strict=False)).
        for binding_op in binding.operations:
            port_op = self._find_port_operation(binding_op.name)
            if port_op is None:
                import warnings
                warnings.warn(
                    f"WSDL binding operation {binding_op.name!r} has no "
                    "matching portType operation; skipping signature "
                    "registration.",
                    stacklevel=2,
                )
                continue
            # For document/literal the soap:body carries no namespace, so the
            # body wrapper must be qualified with the *schema* namespace of the
            # referenced element — which often differs from the WSDL
            # targetNamespace. Fall back to it when the binding has none.
            sig = OperationSignature(
                name=binding_op.name,
                input_params=self._resolve_op_params(port_op.input),
                output_params=self._resolve_op_params(port_op.output),
                soap_action=binding_op.soap_action or "",
                input_namespace=binding_op.input_namespace
                or self._wrapper_namespace(port_op.input),
                output_namespace=binding_op.output_namespace
                or self._wrapper_namespace(port_op.output),
            )
            self.register_operation(sig)

    def _wrapper_namespace(self, op_msg: WsdlOperationMessage | None) -> str | None:
        """Namespace of an operation's document/literal body wrapper element."""
        if op_msg is None or self._wsdl is None:
            return None
        local = op_msg.message.split(":", 1)[-1]
        msg = self._wsdl.messages.get(local)
        if msg is not None and len(msg.parts) == 1 and msg.parts[0].element:
            return msg.parts[0].element_ns
        return None

    def _binding_is_dlw_shaped(
        self, defn: WsdlDefinition, operations: list[Any]
    ) -> bool:
        """Return True if every operation's input/output message looks
        like document-literal-wrapped (one part, element=, element
        local-name matches the operation name — WS-I BP R2201 + R2204).

        An ``xsd:any`` wildcard body (document/literal *bare*, e.g. NF-e's
        ``nfeDadosMsg``) is explicitly *not* wrapped — it must keep its own
        element as the body, not be re-wrapped under the operation name."""
        for bop in operations:
            msg_names = []
            # We only need the message names to inspect shape; reach
            # into port_types for the input/output refs.
            for pt in defn.port_types.values():
                for op in pt.operations:
                    if op.name != bop.name:
                        continue
                    if op.input is not None:
                        msg_names.append(op.input.message)
                    if op.output is not None:
                        msg_names.append(op.output.message)
            for msg_ref in msg_names:
                local = msg_ref.split(":", 1)[-1]
                msg = defn.messages.get(local)
                if msg is None or len(msg.parts) != 1:
                    return False
                part = msg.parts[0]
                if not part.element:
                    return False
                if self._element_is_any_wildcard(part.element.split(":", 1)[-1]):
                    return False
        return True

    def _find_port_operation(self, op_name: str) -> WsdlOperation | None:
        """Locate the portType operation matching ``op_name``."""
        if self._wsdl is None:
            return None
        for pt in self._wsdl.port_types.values():
            for op in pt.operations:
                if op.name == op_name:
                    return op
        return None

    def _resolve_op_params(
        self, op_msg: WsdlOperationMessage | None
    ) -> list[OperationParameter]:
        """Translate a ``WsdlOperationMessage`` (an input/output ref) into
        ``OperationParameter``s. Supports both document-literal (part
        references a global element whose inline complexType enumerates
        the parameters) and RPC-style (one part per parameter with a
        type reference)."""
        if op_msg is None or self._wsdl is None:
            return []
        local = op_msg.message.split(":", 1)[-1]
        msg = self._wsdl.messages.get(local)
        if msg is None:
            return []
        params: list[OperationParameter] = []
        for part in msg.parts:
            if part.element:
                elem_local = part.element.split(":", 1)[-1]
                if self._element_is_any_wildcard(elem_local):
                    # Document/literal BARE: the body *is* this element, which
                    # carries arbitrary XML (xsd:any) passed through verbatim —
                    # e.g. NF-e's <nfeDadosMsg>. One param named after it.
                    from soapbar.core.types import AnyXmlType
                    params.append(
                        OperationParameter(
                            name=elem_local,
                            xsd_type=AnyXmlType(),
                            namespace=part.element_ns,
                        )
                    )
                else:
                    # Document-literal wrapped — the element's inline
                    # complexType sequence carries the actual parameters.
                    params.extend(self._params_from_global_element(elem_local))
            elif part.type:
                # RPC-style — one part per parameter.
                params.append(
                    OperationParameter(
                        name=part.name,
                        xsd_type=self._resolve_xsd_type(part.type),
                    )
                )
        return params

    def _find_global_element(self, element_name: str) -> Any:
        """Locate a global ``<xsd:element name=…>`` declaration in the parsed
        WSDL, or None. Searches ``global_elements`` (soapbar-generated WSDLs)
        then the ``schema_elements`` blocks (externally authored WSDLs)."""
        if self._wsdl is None:
            return None
        from lxml import etree

        xsd_ns = "http://www.w3.org/2001/XMLSchema"
        candidates: list[Any] = list(self._wsdl.global_elements)
        for schema in self._wsdl.schema_elements:
            if isinstance(schema, etree._Element):
                candidates.extend(
                    c for c in schema
                    if isinstance(c.tag, str) and c.tag == f"{{{xsd_ns}}}element"
                )
        for cand in candidates:
            if isinstance(cand, etree._Element) and cand.get("name") == element_name:
                return cand
        return None

    def _element_is_any_wildcard(self, element_name: str) -> bool:
        """True if the global element's content model is an ``xsd:any`` wildcard
        with no named child elements — i.e. a document/literal *bare* body that
        carries arbitrary XML (e.g. NF-e's ``nfeDadosMsg``)."""
        target = self._find_global_element(element_name)
        if target is None:
            return False
        xsd_ns = "http://www.w3.org/2001/XMLSchema"
        ct = target.find(f"{{{xsd_ns}}}complexType")
        if ct is None:
            return False
        seq = ct.find(f"{{{xsd_ns}}}sequence")
        container = seq if seq is not None else ct
        has_any = container.find(f"{{{xsd_ns}}}any") is not None
        has_named = any(
            isinstance(c.tag, str) and c.tag == f"{{{xsd_ns}}}element" for c in container
        )
        return has_any and not has_named

    def _params_from_global_element(
        self, element_name: str
    ) -> list[OperationParameter]:
        """Find a global <xsd:element name=…> in the parsed WSDL and
        return its inline complexType's sequence as OperationParameters."""
        target = self._find_global_element(element_name)
        if target is None:
            return []
        xsd_ns = "http://www.w3.org/2001/XMLSchema"

        # Walk <complexType>/<sequence>/<element> children.
        ct = target.find(f"{{{xsd_ns}}}complexType")
        if ct is None:
            return []
        seq = ct.find(f"{{{xsd_ns}}}sequence")
        if seq is None:
            return []
        params: list[OperationParameter] = []
        for child in seq:
            if not isinstance(child.tag, str):
                continue
            if child.tag != f"{{{xsd_ns}}}element":
                continue
            name = child.get("name")
            type_ref = child.get("type")
            if not name:
                continue
            params.append(
                OperationParameter(
                    name=name,
                    xsd_type=self._resolve_xsd_type(type_ref or "xsd:string"),
                    # minOccurs="0" → optional (e.g. VIES name/address and the
                    # checkVatApprox trader fields). Default minOccurs is 1.
                    required=child.get("minOccurs", "1") != "0",
                )
            )
        return params

    def _resolve_xsd_type(self, type_ref: str) -> Any:
        """Resolve a ``prefix:local`` type reference against the primitive
        xsd registry first, then the WsdlDefinition's complex_types."""
        from soapbar.core.types import xsd as _xsd_registry

        resolved = _xsd_registry.resolve(type_ref)
        if resolved is not None:
            return resolved
        local = type_ref.split(":", 1)[-1] if ":" in type_ref else type_ref
        if self._wsdl is not None and local in self._wsdl.complex_types:
            return self._wsdl.complex_types[local]
        # Fall back to xsd:string so the client at least produces a
        # shaped request rather than crashing on an unresolved type.
        fallback = _xsd_registry.resolve("string")
        if fallback is None:  # pragma: no cover — xsd:string is always registered
            raise RuntimeError(
                "xsd:string type is missing from the xsd registry; "
                "core types are not initialized."
            )
        return fallback

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        use_wsa: bool = False,
        *,
        transport: HttpTransport | None = None,
        endpoint: str | None = None,
    ) -> SoapClient:
        """Build a client from a WSDL file on disk.

        Args:
            path: Path to the WSDL document.
            use_wsa: Enable WS-Addressing request headers.
            transport: Custom :class:`HttpTransport` (e.g. for timeouts, mTLS,
                or a stubbed transport in tests). Defaults to a plain one.
            endpoint: Override the service address parsed from the WSDL — handy
                when the WSDL lists a legacy/HTTP URL but you want HTTPS.
        """
        obj: SoapClient = cls.__new__(cls)
        obj._transport = transport or HttpTransport()
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
        if endpoint is not None:
            obj._address = endpoint
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
