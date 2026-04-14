# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""WSDL builder — generates WSDL XML from WsdlDefinition."""
from __future__ import annotations

import copy
from typing import Any

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
from soapbar.core.wsdl import WsdlBinding, WsdlDefinition
from soapbar.core.xml import make_element, sub_element, to_bytes, to_string


def build_wsdl(defn: WsdlDefinition, address: str) -> _Element:
    tns = defn.target_namespace

    # Determine SOAP ns from bindings
    soap_ns = NS.WSDL_SOAP
    for binding in defn.bindings.values():
        if binding.soap_ns:
            soap_ns = binding.soap_ns
            break

    soap_prefix = "soap12" if soap_ns == NS.WSDL_SOAP12 else "soap"

    nsmap: dict[str | None, str] = {
        None: NS.WSDL,
        "wsdl": NS.WSDL,
        soap_prefix: soap_ns,
        "tns": tns,
        "xsd": NS.XSD,
    }

    root = make_element(
        f"{{{NS.WSDL}}}definitions",
        attrib={
            "name": defn.name,
            "targetNamespace": tns,
        },
        nsmap=nsmap,
    )

    # Types
    if defn.schema_elements or defn.complex_types or defn.global_elements:
        types_elem = sub_element(root, f"{{{NS.WSDL}}}types")
        for schema_elem in defn.schema_elements:
            types_elem.append(copy.deepcopy(schema_elem))
        if defn.complex_types or defn.global_elements:
            schema_elem2 = sub_element(
                types_elem,
                f"{{{NS.XSD}}}schema",
                attrib={
                    "targetNamespace": tns,
                    # WS-I BP R2112 / common-sense interop: schema wire format
                    # is qualified (matches soapbar's serializer output).
                    "elementFormDefault": "qualified",
                },
            )
            # Global <xsd:element> declarations (emitted first so they are
            # discoverable before complex-type bodies reference them).
            for global_elem in defn.global_elements:
                schema_elem2.append(copy.deepcopy(global_elem))
            for ct in defn.complex_types.values():
                if isinstance(ct, ComplexXsdType):
                    schema_elem2.append(_complex_type_to_xsd(ct, tns))
                elif isinstance(ct, ArrayXsdType):
                    schema_elem2.append(_array_type_to_xsd(ct, tns))
                elif isinstance(ct, ChoiceXsdType):
                    schema_elem2.append(_choice_type_to_xsd(ct, tns))

    # Messages
    for msg in defn.messages.values():
        msg_elem = sub_element(root, f"{{{NS.WSDL}}}message", attrib={"name": msg.name})
        for part in msg.parts:
            attrib: dict[str, str] = {"name": part.name}
            if part.element:
                attrib["element"] = part.element
            if part.type:
                attrib["type"] = part.type
            sub_element(msg_elem, f"{{{NS.WSDL}}}part", attrib=attrib)

    # PortTypes
    for pt in defn.port_types.values():
        pt_elem = sub_element(root, f"{{{NS.WSDL}}}portType", attrib={"name": pt.name})
        for op in pt.operations:
            op_elem = sub_element(pt_elem, f"{{{NS.WSDL}}}operation", attrib={"name": op.name})
            if op.documentation:
                sub_element(op_elem, f"{{{NS.WSDL}}}documentation", text=op.documentation)
            if op.input:
                sub_element(
                    op_elem,
                    f"{{{NS.WSDL}}}input",
                    attrib={"message": f"tns:{op.input.message}"},
                )
            if op.output:
                sub_element(
                    op_elem,
                    f"{{{NS.WSDL}}}output",
                    attrib={"message": f"tns:{op.output.message}"},
                )

    # Bindings
    for binding in defn.bindings.values():
        _build_binding(root, binding, soap_ns, soap_prefix, tns)

    # Services
    for svc in defn.services.values():
        svc_elem = sub_element(root, f"{{{NS.WSDL}}}service", attrib={"name": svc.name})
        for port in svc.ports:
            port_elem = sub_element(
                svc_elem,
                f"{{{NS.WSDL}}}port",
                attrib={"name": port.name, "binding": f"tns:{port.binding}"},
            )
            sub_element(
                port_elem,
                f"{{{soap_ns}}}address",
                attrib={"location": address},
            )

    return root


def _build_binding(
    root: _Element,
    binding: WsdlBinding,
    soap_ns: str,
    soap_prefix: str,
    tns: str,
) -> None:
    binding_elem = sub_element(
        root,
        f"{{{NS.WSDL}}}binding",
        attrib={"name": binding.name, "type": f"tns:{binding.port_type}"},
    )
    sub_element(
        binding_elem,
        f"{{{soap_ns}}}binding",
        attrib={"style": binding.style, "transport": binding.transport},
    )

    for op in binding.operations:
        op_elem = sub_element(
            binding_elem,
            f"{{{NS.WSDL}}}operation",
            attrib={"name": op.name},
        )
        soap_op_attrib: dict[str, str] = {"soapAction": op.soap_action}
        if op.style:
            soap_op_attrib["style"] = op.style
        sub_element(op_elem, f"{{{soap_ns}}}operation", attrib=soap_op_attrib)

        # Input body
        input_elem = sub_element(op_elem, f"{{{NS.WSDL}}}input")
        input_body_attrib: dict[str, str] = {"use": op.use or "literal"}
        if op.input_namespace:
            input_body_attrib["namespace"] = op.input_namespace
        sub_element(input_elem, f"{{{soap_ns}}}body", attrib=input_body_attrib)

        # Output body
        output_elem = sub_element(op_elem, f"{{{NS.WSDL}}}output")
        output_body_attrib: dict[str, str] = {"use": op.use or "literal"}
        if op.output_namespace:
            output_body_attrib["namespace"] = op.output_namespace
        sub_element(output_elem, f"{{{soap_ns}}}body", attrib=output_body_attrib)


def build_wsdl_string(defn: WsdlDefinition, address: str) -> str:
    return to_string(build_wsdl(defn, address))


def build_wsdl_bytes(defn: WsdlDefinition, address: str) -> bytes:
    return to_bytes(build_wsdl(defn, address))


# ---------------------------------------------------------------------------
# Complex type → XSD element helpers
# ---------------------------------------------------------------------------

def _type_ref(xsd_type: object) -> str:
    """Return xsd:name or tns:name string for a type."""
    from soapbar.core.types import XsdType
    if isinstance(xsd_type, XsdType):
        ns = getattr(xsd_type, "namespace", "")
        if ns == NS.XSD:
            return f"xsd:{xsd_type.name}"
        return f"tns:{xsd_type.name}"
    return "xsd:string"


def build_doc_literal_wrapper(
    wrapper_name: str,
    params: list[Any],
) -> _Element:
    """Build a global ``<xsd:element>`` declaration for a document/literal
    operation wrapper.

    Emits::

        <xsd:element name="{wrapper_name}">
          <xsd:complexType>
            <xsd:sequence>
              <xsd:element name="{param.name}" type="{param.xsd_type ref}"/>
              …
            </xsd:sequence>
          </xsd:complexType>
        </xsd:element>

    This is the element a WS-I BP R2204-conformant ``<wsdl:part>``
    references via ``element="tns:{wrapper_name}"`` for document/literal
    messages. Each entry in ``params`` must expose ``.name`` and
    ``.xsd_type`` attributes (``OperationParameter`` shape).
    """
    elem = make_element(f"{{{NS.XSD}}}element", attrib={"name": wrapper_name})
    ct = sub_element(elem, f"{{{NS.XSD}}}complexType")
    seq = sub_element(ct, f"{{{NS.XSD}}}sequence")
    for p in params:
        attrib = {"name": p.name, "type": _type_ref(p.xsd_type)}
        sub_element(seq, f"{{{NS.XSD}}}element", attrib=attrib)
    return elem


def _complex_type_to_xsd(ct: ComplexXsdType, tns: str) -> _Element:
    ct_elem = make_element(f"{{{NS.XSD}}}complexType", attrib={"name": ct.name})
    seq = sub_element(ct_elem, f"{{{NS.XSD}}}sequence")
    for field_name, field_type in ct.fields:
        attrib: dict[str, str] = {"name": field_name, "type": _type_ref(field_type)}
        sub_element(seq, f"{{{NS.XSD}}}element", attrib=attrib)
    return ct_elem


def _array_type_to_xsd(ct: ArrayXsdType, tns: str) -> _Element:
    ct_elem = make_element(f"{{{NS.XSD}}}complexType", attrib={"name": ct.name})
    seq = sub_element(ct_elem, f"{{{NS.XSD}}}sequence")
    sub_element(seq, f"{{{NS.XSD}}}element", attrib={
        "name": ct.element_tag,
        "type": _type_ref(ct.element_type),
        "minOccurs": "0",
        "maxOccurs": "unbounded",
    })
    return ct_elem


def _choice_type_to_xsd(ct: ChoiceXsdType, tns: str) -> _Element:
    ct_elem = make_element(f"{{{NS.XSD}}}complexType", attrib={"name": ct.name})
    choice = sub_element(ct_elem, f"{{{NS.XSD}}}choice")
    for opt_name, opt_type in ct.options:
        sub_element(choice, f"{{{NS.XSD}}}element", attrib={
            "name": opt_name,
            "type": _type_ref(opt_type),
        })
    return ct_elem
