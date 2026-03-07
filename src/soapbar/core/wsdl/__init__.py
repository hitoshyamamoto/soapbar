"""WSDL data model dataclasses."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from soapbar.core.binding import BindingStyle

if TYPE_CHECKING:
    from soapbar.core.types import XsdType


@dataclass
class WsdlPart:
    name: str
    element: str | None = None
    type: str | None = None


@dataclass
class WsdlMessage:
    name: str
    parts: list[WsdlPart] = field(default_factory=list)


@dataclass
class WsdlOperationMessage:
    message: str  # QName ref to WsdlMessage
    name: str | None = None


@dataclass
class WsdlOperation:
    name: str
    documentation: str = ""
    input: WsdlOperationMessage | None = None
    output: WsdlOperationMessage | None = None
    faults: list[WsdlOperationMessage] = field(default_factory=list)


@dataclass
class WsdlPortType:
    name: str
    operations: list[WsdlOperation] = field(default_factory=list)


@dataclass
class WsdlBindingOperation:
    name: str
    soap_action: str = ""
    style: str | None = None   # "rpc" or "document" (operation-level override)
    use: str | None = None     # "encoded" or "literal" (operation-level override)
    input_namespace: str | None = None
    output_namespace: str | None = None


@dataclass
class WsdlBinding:
    name: str
    port_type: str  # QName ref
    soap_ns: str = ""           # WSDL_SOAP or WSDL_SOAP12
    style: str = "document"     # binding-level default style
    transport: str = ""
    operations: list[WsdlBindingOperation] = field(default_factory=list)

    def binding_style_for(self, operation_name: str) -> BindingStyle:
        """Determine BindingStyle for a specific operation."""
        op = next((o for o in self.operations if o.name == operation_name), None)
        style = (op.style if op and op.style else None) or self.style
        use = (op.use if op and op.use else None) or "literal"

        if style == "rpc" and use == "encoded":
            return BindingStyle.RPC_ENCODED
        if style == "rpc" and use == "literal":
            return BindingStyle.RPC_LITERAL
        if style == "document" and use == "encoded":
            return BindingStyle.DOCUMENT_ENCODED
        # document + literal (default)
        return BindingStyle.DOCUMENT_LITERAL


@dataclass
class WsdlPort:
    name: str
    binding: str  # QName ref
    address: str = ""


@dataclass
class WsdlService:
    name: str
    ports: list[WsdlPort] = field(default_factory=list)


@dataclass
class WsdlDefinition:
    name: str = ""
    target_namespace: str = ""
    messages: dict[str, WsdlMessage] = field(default_factory=dict)
    port_types: dict[str, WsdlPortType] = field(default_factory=dict)
    bindings: dict[str, WsdlBinding] = field(default_factory=dict)
    services: dict[str, WsdlService] = field(default_factory=dict)
    schema_elements: list[Any] = field(default_factory=list)
    complex_types: dict[str, XsdType] = field(default_factory=dict)

    @property
    def first_service_address(self) -> str | None:
        for svc in self.services.values():
            for port in svc.ports:
                if port.address:
                    return port.address
        return None

    @property
    def first_binding(self) -> WsdlBinding | None:
        return next(iter(self.bindings.values()), None)
