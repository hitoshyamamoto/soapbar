"""SOAP application dispatcher."""
from __future__ import annotations

import logging
import warnings
from typing import Any

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
from soapbar.core.wsdl.builder import _type_ref, build_wsdl_bytes
from soapbar.core.xml import check_xml_depth, to_bytes
from soapbar.server.service import SoapService, _SoapMethod

_log = logging.getLogger(__name__)


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
    ) -> None:
        self._custom_wsdl = custom_wsdl
        self.service_url = service_url
        self._max_body_size = max_body_size
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

    def handle_request(
        self,
        body: bytes,
        soap_action: str = "",
        content_type: str = "text/xml",
    ) -> tuple[int, str, bytes]:
        """Returns (http_status, content_type, response_body)."""
        # Detect SOAP version from content-type
        version = SoapVersion.SOAP_12 if "soap+xml" in content_type else SoapVersion.SOAP_11
        caught_fault: SoapFault = SoapFault("Server", "Unknown internal error")
        http_status = 500
        _mu_tag: str | None = None  # Clark-notation tag of unrecognised mandatory header

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
            for block in envelope.header_blocks:
                if block.must_understand:
                    _mu_tag = str(block.element.tag)
                    raise SoapFault(
                        "MustUnderstand",
                        f"Header not understood: {block.element.tag!s}",
                    )

            # Determine operation name
            op_name = self._resolve_operation(soap_action, envelope)
            if op_name is None:
                raise SoapFault("Client", f"Operation not found for action={soap_action!r}")

            service, method = self._dispatch.get(op_name, (None, None))
            if method is None:
                raise SoapFault("Client", f"Unknown operation: {op_name!r}")

            sig: OperationSignature = method.__soap_operation__
            style = service.__binding_style__  # type: ignore[union-attr]
            serializer = get_serializer(style)

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

        if version == SoapVersion.SOAP_11:
            fault_elem = caught_fault.to_soap11_envelope()
        else:
            # SOAP 1.2: attach required/recommended header blocks per spec
            _fault_headers = []
            if caught_fault.faultcode == "VersionMismatch":
                # [SOAP12-P1] §5.4.7 MUST include Upgrade header
                _fault_headers.append(build_upgrade_header_block())
            elif caught_fault.faultcode == "MustUnderstand" and _mu_tag is not None:
                # [SOAP12-P1] §5.4.8 SHOULD include NotUnderstood header
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

                # Input message
                in_msg_name = f"{op_name}Request"
                in_parts = [
                    WsdlPart(name=p.name, type=_type_ref(p.xsd_type))
                    for p in sig.input_params
                ]
                defn.messages[in_msg_name] = WsdlMessage(name=in_msg_name, parts=in_parts)

                # Output message
                out_msg_name = f"{op_name}Response"
                out_parts = [
                    WsdlPart(name=p.name, type=_type_ref(p.xsd_type))
                    for p in sig.output_params
                ]
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
