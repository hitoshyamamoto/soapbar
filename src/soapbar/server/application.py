"""SOAP application dispatcher."""
from __future__ import annotations

from typing import Any

from soapbar.core.binding import (
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import SoapEnvelope, SoapVersion
from soapbar.core.fault import SoapFault
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
from soapbar.core.wsdl.builder import build_wsdl_bytes
from soapbar.core.xml import to_bytes
from soapbar.server.service import SoapService


class SoapApplication:
    def __init__(
        self,
        custom_wsdl: bytes | None = None,
        service_url: str = "http://localhost:8000/soap",
    ) -> None:
        self._custom_wsdl = custom_wsdl
        self.service_url = service_url
        self._services: list[SoapService] = []
        # operation_name → (service, method)
        self._dispatch: dict[str, tuple[SoapService, Any]] = {}
        # soap_action → operation_name
        self._action_map: dict[str, str] = {}

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

        try:
            envelope = SoapEnvelope.from_xml(body)
            version = envelope.version

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

            body_elem = envelope.first_body_element
            if body_elem is None:
                raise SoapFault("Client", "Empty SOAP Body")

            # Wrap body_elem in a dummy container for deserializer
            from lxml import etree
            container = etree.Element("_body")
            container.append(body_elem)

            kwargs = serializer.deserialize_request(sig, container)

            # Call the service method
            result = method(**kwargs)

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

            resp_bytes = resp_envelope.to_bytes()
            return 200, version.content_type, resp_bytes

        except SoapFault as sf:
            http_status = 500
            # Client faults → 400
            if sf.faultcode.startswith("Client") or sf.faultcode.startswith("Sender"):
                http_status = 400
            fault_elem = (
                sf.to_soap11_envelope() if version == SoapVersion.SOAP_11
                else sf.to_soap12_envelope()
            )
            return http_status, version.content_type, to_bytes(fault_elem)

        except Exception as exc:
            sf = SoapFault("Server", f"Internal error: {exc}")
            fault_elem = (
                sf.to_soap11_envelope() if version == SoapVersion.SOAP_11
                else sf.to_soap12_envelope()
            )
            return 500, version.content_type, to_bytes(fault_elem)

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
                    WsdlPart(name=p.name, type=f"xsd:{p.xsd_type.name}")
                    for p in sig.input_params
                ]
                defn.messages[in_msg_name] = WsdlMessage(name=in_msg_name, parts=in_parts)

                # Output message
                out_msg_name = f"{op_name}Response"
                out_parts = [
                    WsdlPart(name=p.name, type=f"xsd:{p.xsd_type.name}")
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
