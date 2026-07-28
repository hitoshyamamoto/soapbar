# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""WSDL data model dataclasses."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from soapbar.core.binding import BindingStyle

if TYPE_CHECKING:
    from soapbar.core.types import XsdType


@dataclass
class WsdlPart:
    """A ``wsdl:part`` of a message: a named reference to an element or type."""

    name: str
    element: str | None = None
    type: str | None = None
    # Namespace URI of the referenced ``element`` (resolved from its QName
    # prefix at parse time). For document/literal this is the schema namespace
    # the body wrapper must be qualified with — which often differs from the
    # WSDL targetNamespace (e.g. EU VIES uses a separate ``…:types`` schema).
    element_ns: str | None = None


@dataclass
class WsdlMessage:
    """A ``wsdl:message``: a named list of ``WsdlPart`` entries."""

    name: str
    parts: list[WsdlPart] = field(default_factory=list)


@dataclass
class WsdlOperationMessage:
    """An operation's input/output/fault slot referencing a message by QName."""

    message: str  # QName ref to WsdlMessage
    name: str | None = None


@dataclass
class WsdlOperation:
    """A ``wsdl:operation`` in a port type: name, documentation, and its
    input/output/fault message references."""

    name: str
    documentation: str = ""
    input: WsdlOperationMessage | None = None
    output: WsdlOperationMessage | None = None
    faults: list[WsdlOperationMessage] = field(default_factory=list)


@dataclass
class WsdlPortType:
    """A ``wsdl:portType``: the abstract interface, a named set of operations."""

    name: str
    operations: list[WsdlOperation] = field(default_factory=list)


@dataclass
class WsdlBindingOperation:
    """Per-operation SOAP binding details: ``soapAction``, style and use
    overrides, and input/output body namespaces."""

    name: str
    soap_action: str = ""
    style: str | None = None   # "rpc" or "document" (operation-level override)
    use: str | None = None        # input use: "encoded" or "literal"
    output_use: str | None = None # output use: "encoded" or "literal" (may differ from input)
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
    """A ``wsdl:port``: a binding bound to a concrete endpoint address."""

    name: str
    binding: str  # QName ref
    address: str = ""


@dataclass
class WsdlService:
    """A ``wsdl:service``: a named collection of ``WsdlPort`` entries."""

    name: str
    ports: list[WsdlPort] = field(default_factory=list)


@dataclass
class WsdlDefinition:
    """In-memory model of a complete WSDL 1.1 document.

    Produced by ``parse_wsdl`` / ``parse_wsdl_file`` and consumed by
    ``build_wsdl``; messages, port types, bindings, and services are keyed
    by local name, with parsed schema types in ``complex_types``.
    """

    name: str = ""
    target_namespace: str = ""
    messages: dict[str, WsdlMessage] = field(default_factory=dict)
    port_types: dict[str, WsdlPortType] = field(default_factory=dict)
    bindings: dict[str, WsdlBinding] = field(default_factory=dict)
    services: dict[str, WsdlService] = field(default_factory=dict)
    schema_elements: list[Any] = field(default_factory=list)
    complex_types: dict[str, XsdType] = field(default_factory=dict)
    # The scoped type registry this definition's parsed types resolve against
    # (a ``_TypeRegistry``; ``Any`` to avoid importing it here). Populated by
    # parse_wsdl; None for hand-built definitions, which use the global built-ins.
    type_registry: Any = None
    # Global <xsd:element> declarations synthesized for document/literal
    # operations so <wsdl:part element="tns:…"/> can reference them per
    # WS-I BP 1.1 R2204. Each entry is an already-built lxml Element in
    # the XSD namespace. Inserted into the main schema block by the
    # builder alongside complex_types.
    global_elements: list[Any] = field(default_factory=list)

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
