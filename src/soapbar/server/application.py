# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""SOAP application dispatcher."""
from __future__ import annotations

import logging
import warnings
from collections.abc import Callable
from typing import Any, Literal

from soapbar.core.binding import (
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import SoapEnvelope, SoapVersion, build_wsa_response_headers
from soapbar.core.fault import (
    SoapFault,
    build_not_understood_header_block,
    build_upgrade_header_block,
)
from soapbar.core.namespaces import NS
from soapbar.core.wsdl import (
    WsdlBinding,
    WsdlBindingOperation,
    WsdlDefinition,
    WsdlMessage,
    WsdlOperation,
    WsdlOperationMessage,
    WsdlPart,
    WsdlPort,
    WsdlPortType,
    WsdlService,
)
from soapbar.core.wsdl.builder import (
    _type_ref,
    build_doc_literal_wrapper,
    build_wsdl_bytes,
)
from soapbar.core.xml import check_xml_depth, compile_schema, to_bytes, validate_schema
from soapbar.server.service import SoapService, _SoapMethod

_log = logging.getLogger(__name__)


def _accepts_json(accept: str) -> bool:
    """Return True if ``accept`` contains ``application/json`` as a discrete media type.

    A negative lookahead excludes suffixed types such as
    ``application/json-patch+json`` or ``application/json+ld``
    (RFC 7231 §5.3.2).
    """
    import re
    return bool(re.search(r"(?:^|[\s,])application/json(?![-+\w])", accept))


def _json_default(obj: Any) -> Any:
    """Fallback serializer for ``json.dumps`` in JSON dual-mode responses.

    Handles ``bytes``, date/time objects, ``Decimal``, and any other type
    by falling back to ``str()``.
    """
    import base64

    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(obj).decode("ascii")
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def _validate_input_params(sig: OperationSignature, kwargs: dict[str, Any]) -> None:
    """Validate deserialized request parameters against the operation signature.

    Raises ``SoapFault("Client", ...)`` for any required parameter that is
    absent from *kwargs* or whose value is ``None``.  This check runs before
    the service handler is invoked so that schema violations produce a clean,
    spec-compliant Client fault instead of an unhandled Python TypeError or
    AttributeError from inside the handler.
    """
    missing = [
        p.name
        for p in sig.input_params
        if p.required and kwargs.get(p.name) is None
    ]
    if missing:
        params = ", ".join(missing)
        raise SoapFault(
            "Client",
            f"Missing required input parameter(s): {params}",
        )


class SoapApplication:
    def __init__(
        self,
        custom_wsdl: bytes | None = None,
        service_url: str = "http://localhost:8000/soap",
        max_body_size: int = 10 * 1024 * 1024,  # 10 MB — G01
        security_validator: Any = None,
        validate_body_schema: bool = False,
        allow_plaintext_credentials: bool = False,
        wsdl_access: Literal["public", "authenticated", "disabled"] = "public",
        wsdl_auth_hook: Callable[[dict[str, str]], bool] | None = None,
    ) -> None:
        self._custom_wsdl = custom_wsdl
        self.service_url = service_url
        self._max_body_size = max_body_size
        self._security_validator = security_validator  # G09: UsernameTokenValidator or None
        self._validate_body_schema = validate_body_schema  # X07
        self._allow_plaintext_credentials = allow_plaintext_credentials  # S08
        self._wsdl_access = wsdl_access  # X06
        self._wsdl_auth_hook = wsdl_auth_hook  # X06
        self._compiled_schema: Any = None  # etree.XMLSchema | None; lazy-built
        self._services: list[SoapService] = []
        # operation_name → (service, method)
        self._dispatch: dict[str, tuple[SoapService, _SoapMethod]] = {}
        # soap_action → operation_name
        self._action_map: dict[str, str] = {}
        # G11 — warn if service_url is plain HTTP (not HTTPS)
        if service_url.startswith("http://"):
            warnings.warn(
                f"service_url uses plain HTTP ({service_url!r}). "
                "Use HTTPS in production to protect SOAP message confidentiality.",
                UserWarning,
                stacklevel=2,
            )
            # N06 — additional warning when a security validator is configured over HTTP:
            # PasswordText credentials will be transmitted in cleartext.
            if security_validator is not None:
                warnings.warn(
                    "security_validator is set but service_url uses plain HTTP. "
                    "PasswordText credentials will be exposed in transit. "
                    "Use HTTPS or PasswordDigest to protect credentials.",
                    UserWarning,
                    stacklevel=2,
                )

    def _get_compiled_schema(self) -> Any:
        """Return a compiled lxml XMLSchema from registered services' WSDL types.

        Builds a composite ``<xs:schema>`` element that imports each inline
        ``<xsd:schema>`` block found in the registered services' WSDL types
        sections, then compiles it once and caches the result.

        Returns ``None`` if no embedded schemas are available.
        """
        if self._compiled_schema is not None:
            return self._compiled_schema

        from lxml import etree

        # Collect all <xsd:schema> elements from the combined WSDL definition
        schema_elems: list[Any] = []
        defn = self._build_wsdl_definition()
        schema_elems.extend(defn.schema_elements)

        if not schema_elems:
            return None

        # Build a wrapper schema that imports all discovered schemas via xs:any
        # For validation purposes, build a single combined schema element.
        # If there is exactly one, use it directly.  If there are multiple,
        # wrap them in a single xs:schema with xs:import directives.
        xsd_ns = NS.XSD
        if len(schema_elems) == 1:
            try:
                self._compiled_schema = compile_schema(schema_elems[0])
                return self._compiled_schema
            except etree.XMLSchemaParseError:
                return None

        # Multiple schemas: create a composite wrapper
        wrapper = etree.Element(f"{{{xsd_ns}}}schema", nsmap={"xs": xsd_ns})
        for s in schema_elems:
            tns = s.get("targetNamespace", "")
            imp = etree.SubElement(wrapper, f"{{{xsd_ns}}}import")
            if tns:
                imp.set("namespace", tns)
            for child in s:
                wrapper.append(child)
        try:
            self._compiled_schema = compile_schema(wrapper)
        except etree.XMLSchemaParseError:
            return None
        return self._compiled_schema

    def register(self, service: SoapService) -> None:
        self._services.append(service)
        for op_name, method in service.get_operations().items():
            self._dispatch[op_name] = (service, method)
            sig: OperationSignature = method.__soap_operation__
            if sig.soap_action:
                self._action_map[sig.soap_action] = op_name
                # Also register without quotes / with cleaned action
                clean = sig.soap_action.strip('"')
                if clean != sig.soap_action:
                    self._action_map[clean] = op_name

    def get_wsdl(self) -> bytes:
        if self._custom_wsdl is not None:
            return self._custom_wsdl
        defn = self._build_wsdl_definition()
        return build_wsdl_bytes(defn, self.service_url)

    def check_wsdl_access(self, headers: dict[str, str]) -> bool:
        """Return True if the WSDL may be served for the given request headers.

        Controlled by the *wsdl_access* constructor parameter:

        - ``"public"`` (default) — always allowed.
        - ``"disabled"`` — always denied (returns 403).
        - ``"authenticated"`` — delegates to *wsdl_auth_hook*; denied if no
          hook is configured.
        """
        if self._wsdl_access == "disabled":
            return False
        if self._wsdl_access == "authenticated":
            return self._wsdl_auth_hook(headers) if self._wsdl_auth_hook is not None else False
        return True  # "public"

    def handle_request(
        self,
        body: bytes,
        soap_action: str = "",
        content_type: str = "text/xml",
        accept_header: str = "",
    ) -> tuple[int, str, bytes]:
        """Returns (http_status, content_type, response_body)."""
        # Detect SOAP version from content-type
        version = SoapVersion.SOAP_12 if "soap+xml" in content_type else SoapVersion.SOAP_11
        caught_fault: SoapFault = SoapFault("Server", "Unknown internal error")
        http_status = 500
        _mu_tags: list[str] = []  # Clark-notation tags of unrecognised mandatory headers
        _request_wsa: Any = None  # WsaHeaders | None — captured for fault response (N09)

        try:
            # G01 — reject oversized requests before any XML parsing
            if len(body) > self._max_body_size:
                raise SoapFault(
                    "Client",
                    f"Request body size ({len(body)} bytes) exceeds the "
                    f"server limit ({self._max_body_size} bytes).",
                )

            # G03 — reject deeply nested XML before full parse (DoS prevention)
            check_xml_depth(body)

            envelope = SoapEnvelope.from_xml(body)
            version = envelope.version
            _request_wsa = envelope.ws_addressing  # N09: used in fault response if needed

            # DataEncodingUnknown enforcement (SOAP 1.2 §5.4.9 MUST)
            # Only SOAP 1.2 defines this fault code; SOAP 1.1 has no equivalent.
            if version == SoapVersion.SOAP_12:
                _enc_attr = f"{{{NS.SOAP12_ENV}}}encodingStyle"
                for body_elem in envelope.body_elements:
                    enc = body_elem.get(_enc_attr, "")
                    if enc and enc != NS.SOAP12_ENC:
                        raise SoapFault(
                            "DataEncodingUnknown",
                            f"Encoding style not supported: {enc!r}",
                        )

            # mustUnderstand enforcement (SOAP 1.1 §4.2.3, SOAP 1.2 §5.2.3)
            # Headers whose namespaces are understood by this endpoint are whitelisted.
            _understood_ns = {NS.WSA}
            if self._security_validator is not None:
                _understood_ns.add(NS.WSSE)
            for block in envelope.header_blocks:
                if block.must_understand:
                    from soapbar.core.xml import namespace_uri as _ns_uri
                    if _ns_uri(block.element) not in _understood_ns:
                        _mu_tags.append(str(block.element.tag))
            if _mu_tags:
                raise SoapFault(
                    "MustUnderstand",
                    f"Header(s) not understood: {', '.join(_mu_tags)}",
                )

            # G09: WS-Security validation
            if self._security_validator is not None:
                if envelope.ws_security_element is None:
                    raise SoapFault("Client", "Missing wsse:Security header")

                # S08 — reject PasswordText over plain HTTP unless explicitly opted in
                # (WSS 1.0 §6.2; WS-I BSP R4202).
                if (
                    not self._allow_plaintext_credentials
                    and self.service_url.startswith("http://")
                ):
                    _wsse_ns = NS.WSSE
                    for _ut in envelope.ws_security_element.findall(
                        f"{{{_wsse_ns}}}UsernameToken"
                    ):
                        _pw = _ut.find(f"{{{_wsse_ns}}}Password")
                        if _pw is not None and (_pw.get("Type") or "").endswith("#PasswordText"):
                            raise SoapFault(
                                "Client",
                                "PasswordText credentials are not permitted over a non-TLS "
                                "transport (WSS 1.0 §6.2). Use HTTPS or PasswordDigest. "
                                "Set allow_plaintext_credentials=True to override in "
                                "development.",
                            )

                from soapbar.core.wssecurity import SecurityValidationError
                try:
                    self._security_validator.validate(envelope.ws_security_element)
                except SecurityValidationError as exc:
                    raise SoapFault("Client", f"Security validation failed: {exc}") from exc

            # Determine operation name
            op_name = self._resolve_operation(soap_action, envelope)
            if op_name is None:
                raise SoapFault("Client", f"Operation not found for action={soap_action!r}")

            service, method = self._dispatch.get(op_name, (None, None))
            if method is None:
                raise SoapFault("Client", f"Unknown operation: {op_name!r}")

            sig: OperationSignature = method.__soap_operation__
            style = service.__binding_style__  # type: ignore[union-attr]
            serializer = get_serializer(style, version)

            if not envelope.body_elements:
                raise SoapFault("Client", "Empty SOAP Body")

            # Wrap all body children in a dummy container for deserializer.
            # RPC/wrapped styles have one wrapper element; document styles may
            # have multiple sibling parameters as direct body children.
            from lxml import etree
            container = etree.Element("_body")
            for body_elem in envelope.body_elements:
                container.append(body_elem)

            kwargs = serializer.deserialize_request(sig, container)

            # F09 — validate required input parameters before dispatch
            _validate_input_params(sig, kwargs)

            # X07 — optional WSDL schema validation of Body elements
            if self._validate_body_schema:
                schema = self._get_compiled_schema()
                if schema is not None:
                    for body_elem in list(container):
                        if not validate_schema(schema, body_elem):
                            errors = schema.error_log
                            first = errors[0].message if errors else "schema mismatch"
                            raise SoapFault("Client", f"Schema validation failed: {first}")

            # Call the service method
            result = method(**kwargs)

            # G08 — one-way MEP: HTTP 202 Accepted, empty body (SOAP 1.2 P2 §7.5.1)
            if sig.one_way:
                return 202, version.content_type, b""

            # Build response
            if isinstance(result, dict):
                values = result
            elif result is None:
                values = {}
            else:
                # Single return value
                values = (
                    {sig.output_params[0].name: result} if sig.output_params else {}
                )

            # JSON dual-mode: if the client prefers JSON, skip SOAP serialization
            if _accepts_json(accept_header):
                import json as _json
                return 200, "application/json; charset=utf-8", _json.dumps(
                    values, default=_json_default,
                ).encode()

            from lxml import etree as _etree
            resp_envelope = SoapEnvelope(version=version)
            resp_body_container = _etree.Element("_body")
            serializer.serialize_response(sig, values, resp_body_container)
            for child in resp_body_container:
                resp_envelope.add_body_content(child)

            # WS-Addressing: echo MessageID as RelatesTo, generate new MessageID
            if envelope.ws_addressing is not None:
                req_action = envelope.ws_addressing.action
                resp_action = (req_action + "Response") if req_action else None
                for hdr in build_wsa_response_headers(
                    envelope.ws_addressing, action=resp_action
                ):
                    resp_envelope.add_header(hdr)

            resp_bytes = resp_envelope.to_bytes()
            return 200, version.content_type, resp_bytes

        except SoapFault as exc_sf:
            caught_fault = exc_sf

        except (ValueError, TypeError) as exc:
            caught_fault = SoapFault("Client", str(exc))

        except Exception as exc:
            # G02 — log full exception server-side; return generic message to client
            _log.exception("Unhandled exception during SOAP request processing: %s", exc)
            caught_fault = SoapFault("Server", "An internal error occurred.")
            http_status = 500

        # JSON dual-mode: return JSON fault body when client prefers JSON
        if _accepts_json(accept_header):
            import json as _json
            _fault_body = {
                "fault": {
                    "code": caught_fault.faultcode,
                    "message": caught_fault.faultstring,
                },
            }
            if caught_fault.detail is not None:
                _fault_body["fault"]["detail"] = (
                    caught_fault.detail
                    if isinstance(caught_fault.detail, str)
                    else str(caught_fault.detail)
                )
            return (
                http_status,
                "application/json; charset=utf-8",
                _json.dumps(_fault_body, default=_json_default).encode(),
            )

        # N09 — WS-Addressing fault headers: route to FaultTo EPR when present
        _fault_wsa_headers: list[Any] = []
        if _request_wsa is not None:
            from soapbar.core.xml import make_element as _make_elem
            _wsa_ns = NS.WSA
            _wsa_nsmap: dict[str | None, str] = {"wsa": _wsa_ns}
            # wsa:To → FaultTo address (or ReplyTo if FaultTo absent)
            _fault_epr = _request_wsa.fault_to or _request_wsa.reply_to
            if _fault_epr and _fault_epr.address not in (
                "", "http://www.w3.org/2005/08/addressing/none"
            ):
                _to = _make_elem(f"{{{_wsa_ns}}}To", nsmap=_wsa_nsmap)
                _to.text = _fault_epr.address
                _fault_wsa_headers.append(_to)
            # wsa:RelatesTo → request MessageID
            if _request_wsa.message_id:
                _rel = _make_elem(f"{{{_wsa_ns}}}RelatesTo", nsmap=_wsa_nsmap)
                _rel.text = _request_wsa.message_id
                _fault_wsa_headers.append(_rel)
            # wsa:Action → standard fault action URI
            _act = _make_elem(f"{{{_wsa_ns}}}Action", nsmap=_wsa_nsmap)
            _act.text = "http://www.w3.org/2005/08/addressing/fault"
            _fault_wsa_headers.append(_act)

        if version == SoapVersion.SOAP_11:
            fault_elem = caught_fault.to_soap11_envelope(
                header_blocks=_fault_wsa_headers or None,
            )
        else:
            # SOAP 1.2: attach required/recommended header blocks per spec
            _fault_headers: list[Any] = list(_fault_wsa_headers)
            if caught_fault.faultcode == "VersionMismatch":
                # [SOAP12-P1] §5.4.7 MUST include Upgrade header
                _fault_headers.append(build_upgrade_header_block())
            elif caught_fault.faultcode == "MustUnderstand" and _mu_tags:
                # [SOAP12-P1] §5.4.8 SHOULD include one NotUnderstood block per header
                for _mu_tag in _mu_tags:
                    _fault_headers.append(build_not_understood_header_block(_mu_tag))
            fault_elem = caught_fault.to_soap12_envelope(
                header_blocks=_fault_headers or None,
            )
        return http_status, version.content_type, to_bytes(fault_elem)

    def _resolve_operation(
        self,
        soap_action: str,
        envelope: SoapEnvelope,
    ) -> str | None:
        # 1. Try SOAPAction header
        clean_action = soap_action.strip('"').strip()
        if clean_action and clean_action in self._action_map:
            return self._action_map[clean_action]
        if soap_action in self._action_map:
            return self._action_map[soap_action]

        # 2. Check if action matches a fragment like "#OpName"
        if clean_action.startswith("#"):
            candidate = clean_action[1:]
            if candidate in self._dispatch:
                return candidate

        # 3. Fall back to body element local name
        op_name = envelope.operation_name
        if op_name and op_name in self._dispatch:
            return op_name

        return None

    def _build_wsdl_definition(self) -> WsdlDefinition:
        """Auto-generate WsdlDefinition from registered services."""
        if not self._services:
            return WsdlDefinition(target_namespace="http://example.com/soap")

        svc = self._services[0]
        tns = svc.__tns__
        service_name = svc.__service_name__ or svc.__class__.__name__
        binding_style = svc.__binding_style__
        soap_version = svc.__soap_version__
        port_name = svc.__port_name__ or f"{service_name}Port"

        soap_ns = NS.WSDL_SOAP if soap_version == SoapVersion.SOAP_11 else NS.WSDL_SOAP12
        transport = "http://schemas.xmlsoap.org/soap/http"

        defn = WsdlDefinition(
            name=service_name,
            target_namespace=tns,
        )

        pt = WsdlPortType(name=f"{service_name}PortType")
        binding_ops: list[WsdlBindingOperation] = []

        for svc_instance in self._services:
            for op_name, method in svc_instance.get_operations().items():
                sig: OperationSignature = method.__soap_operation__
                doc = getattr(method, "__soap_documentation__", "")

                # Synthesize global <xsd:element> wrappers for doc/literal
                # operations (WS-I BP R2204 prerequisite). Only DLW emits
                # wrappers here; plain DOCUMENT_LITERAL and RPC-style
                # messages continue to reference per-parameter types.
                if binding_style.is_wrapped:
                    defn.global_elements.append(
                        build_doc_literal_wrapper(op_name, sig.input_params)
                    )
                    defn.global_elements.append(
                        build_doc_literal_wrapper(
                            f"{op_name}Response", sig.output_params
                        )
                    )

                # Input / output messages. WS-I BP R2201 + R2204:
                # document-literal-wrapped messages MUST contain exactly one
                # part, and that part MUST reference a global xsd:element
                # (not xsd:type). RPC-style and encoded styles keep the
                # per-parameter `type=` shape permitted by the profile.
                in_msg_name = f"{op_name}Request"
                out_msg_name = f"{op_name}Response"
                if binding_style.is_wrapped:
                    in_parts = [
                        WsdlPart(name="parameters", element=f"tns:{op_name}")
                    ]
                    out_parts = [
                        WsdlPart(
                            name="parameters",
                            element=f"tns:{op_name}Response",
                        )
                    ]
                else:
                    in_parts = [
                        WsdlPart(name=p.name, type=_type_ref(p.xsd_type))
                        for p in sig.input_params
                    ]
                    out_parts = [
                        WsdlPart(name=p.name, type=_type_ref(p.xsd_type))
                        for p in sig.output_params
                    ]
                defn.messages[in_msg_name] = WsdlMessage(name=in_msg_name, parts=in_parts)
                defn.messages[out_msg_name] = WsdlMessage(name=out_msg_name, parts=out_parts)

                # PortType operation
                pt.operations.append(WsdlOperation(
                    name=op_name,
                    documentation=doc,
                    input=WsdlOperationMessage(message=in_msg_name),
                    output=WsdlOperationMessage(message=out_msg_name),
                ))

                binding_ops.append(WsdlBindingOperation(
                    name=op_name,
                    soap_action=sig.soap_action,
                    style=binding_style.soap_style,
                    use=binding_style.soap_use,
                    input_namespace=sig.input_namespace or tns,
                    output_namespace=sig.output_namespace or tns,
                ))

        defn.port_types[pt.name] = pt

        binding_name = f"{service_name}Binding"
        defn.bindings[binding_name] = WsdlBinding(
            name=binding_name,
            port_type=pt.name,
            soap_ns=soap_ns,
            style=binding_style.soap_style,
            transport=transport,
            operations=binding_ops,
        )

        wsdl_port = WsdlPort(
            name=port_name,
            binding=binding_name,
            address=self.service_url,
        )
        defn.services[service_name] = WsdlService(
            name=service_name,
            ports=[wsdl_port],
        )

        return defn
