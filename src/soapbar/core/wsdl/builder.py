"""WSDL builder — generates WSDL XML from WsdlDefinition."""
from __future__ import annotations

from lxml.etree import _Element

from soapbar.core.namespaces import NS
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
    if defn.schema_elements:
        types_elem = sub_element(root, f"{{{NS.WSDL}}}types")
        for schema_elem in defn.schema_elements:
            types_elem.append(schema_elem)

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
