"""WSDL parser — supports SOAP 1.1 and SOAP 1.2 binding extensions."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType, XsdType, xsd
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
from soapbar.core.xml import local_name, namespace_uri, parse_xml_document

_WSDL = NS.WSDL
_SOAP_NS_SET = {NS.WSDL_SOAP, NS.WSDL_SOAP12}


def _resolve_qname(qname: str, nsmap: dict[str, str]) -> str:
    """Resolve prefix:local → {ns}local using nsmap."""
    if ":" in qname:
        prefix, local = qname.split(":", 1)
        ns = nsmap.get(prefix, "")
        return f"{{{ns}}}{local}" if ns else local
    return qname


def _local(qname: str) -> str:
    """Extract local name from Clark or prefix:local notation."""
    if qname.startswith("{"):
        return qname.split("}", 1)[1]
    if ":" in qname:
        return qname.split(":", 1)[1]
    return qname


def _resolve_location(location: str, base_url: str | None) -> str:
    if base_url and not location.startswith(("http://", "https://", "file://")):
        return urljoin(base_url, location)
    return location


def _fetch_wsdl_source(location: str) -> bytes:
    if location.startswith(("http://", "https://")):
        import urllib.request
        with urllib.request.urlopen(location) as resp:  # noqa: S310
            return resp.read()  # type: ignore[no-any-return]
    return Path(location).read_bytes()


def _merge_definition(target: WsdlDefinition, source: WsdlDefinition) -> None:
    target.messages.update(source.messages)
    target.port_types.update(source.port_types)
    target.bindings.update(source.bindings)
    target.services.update(source.services)
    target.schema_elements.extend(source.schema_elements)


def parse_wsdl(
    source: str | bytes | Path | _Element,
    base_url: str | None = None,
    _visited: set[str] | None = None,
) -> WsdlDefinition:
    if _visited is None:
        _visited = set()
    root = parse_xml_document(source)
    nsmap: dict[str, str] = {k: v for k, v in root.nsmap.items() if k is not None}

    defn = WsdlDefinition(
        name=root.get("name", ""),
        target_namespace=root.get("targetNamespace", ""),
    )

    for child in root:
        lname = local_name(child)

        if lname == "import":
            location = child.get("location")
            if location:
                resolved = _resolve_location(location, base_url)
                if resolved not in _visited:
                    _visited.add(resolved)
                    imported = parse_wsdl(
                        _fetch_wsdl_source(resolved),
                        base_url=resolved,
                        _visited=_visited,
                    )
                    _merge_definition(defn, imported)
            # namespace-only import (no location=) is silently skipped

        elif lname == "types":
            defn.schema_elements = list(child)
            for schema in child:
                if local_name(schema) == "schema":
                    parsed = _parse_schema_types(schema, nsmap)
                    defn.complex_types.update(parsed)
                    for t in parsed.values():
                        xsd.register(t)

        elif lname == "message":
            msg = _parse_message(child)
            defn.messages[msg.name] = msg

        elif lname == "portType":
            pt = _parse_port_type(child)
            defn.port_types[pt.name] = pt

        elif lname == "binding":
            binding = _parse_binding(child, nsmap)
            if binding is not None:
                defn.bindings[binding.name] = binding

        elif lname == "service":
            svc = _parse_service(child)
            defn.services[svc.name] = svc

    return defn


def parse_wsdl_file(path: str | Path) -> WsdlDefinition:
    p = Path(path)
    return parse_wsdl(p, base_url=p.resolve().parent.as_uri() + "/")


# ---------------------------------------------------------------------------
# Internal parsers
# ---------------------------------------------------------------------------

def _parse_message(elem: _Element) -> WsdlMessage:
    name = elem.get("name", "")
    parts: list[WsdlPart] = []
    for child in elem:
        if local_name(child) == "part":
            parts.append(WsdlPart(
                name=child.get("name", ""),
                element=child.get("element"),
                type=child.get("type"),
            ))
    return WsdlMessage(name=name, parts=parts)


def _parse_port_type(elem: _Element) -> WsdlPortType:
    name = elem.get("name", "")
    operations: list[WsdlOperation] = []
    for child in elem:
        if local_name(child) == "operation":
            operations.append(_parse_port_type_operation(child))
    return WsdlPortType(name=name, operations=operations)


def _parse_port_type_operation(elem: _Element) -> WsdlOperation:
    name = elem.get("name", "")
    doc = ""
    input_msg: WsdlOperationMessage | None = None
    output_msg: WsdlOperationMessage | None = None
    faults: list[WsdlOperationMessage] = []

    for child in elem:
        lname = local_name(child)
        if lname == "documentation":
            doc = child.text or ""
        elif lname == "input":
            msg_ref = child.get("message", "")
            input_msg = WsdlOperationMessage(message=_local(msg_ref), name=child.get("name"))
        elif lname == "output":
            msg_ref = child.get("message", "")
            output_msg = WsdlOperationMessage(message=_local(msg_ref), name=child.get("name"))
        elif lname == "fault":
            msg_ref = child.get("message", "")
            faults.append(WsdlOperationMessage(message=_local(msg_ref), name=child.get("name")))

    return WsdlOperation(
        name=name,
        documentation=doc,
        input=input_msg,
        output=output_msg,
        faults=faults,
    )


def _parse_binding(elem: _Element, nsmap: dict[str, str]) -> WsdlBinding | None:
    name = elem.get("name", "")
    port_type_ref = elem.get("type", "")
    port_type = _local(port_type_ref)

    # Find SOAP extension element
    soap_binding: _Element | None = None
    soap_ns_used = ""
    for child in elem:
        child_ns = namespace_uri(child)
        if child_ns in _SOAP_NS_SET and local_name(child) == "binding":
            soap_binding = child
            soap_ns_used = child_ns or ""
            break

    if soap_binding is None:
        # Not a SOAP binding; skip
        return None

    style = soap_binding.get("style", "document")
    transport = soap_binding.get("transport", "")

    binding = WsdlBinding(
        name=name,
        port_type=port_type,
        soap_ns=soap_ns_used,
        style=style,
        transport=transport,
    )

    for child in elem:
        if local_name(child) == "operation":
            binding.operations.append(_parse_binding_operation(child, soap_ns_used))

    return binding


def _parse_binding_operation(elem: _Element, soap_ns: str) -> WsdlBindingOperation:
    name = elem.get("name", "")
    soap_action = ""
    style: str | None = None
    input_namespace: str | None = None
    output_namespace: str | None = None
    input_use: str | None = None

    for child in elem:
        child_ns = namespace_uri(child)
        lname = local_name(child)

        if child_ns == soap_ns and lname == "operation":
            soap_action = child.get("soapAction", "")
            style = child.get("style")

        elif lname == "input":
            for grandchild in child:
                if namespace_uri(grandchild) == soap_ns and local_name(grandchild) == "body":
                    input_namespace = grandchild.get("namespace")
                    input_use = grandchild.get("use")

        elif lname == "output":
            for grandchild in child:
                if namespace_uri(grandchild) == soap_ns and local_name(grandchild) == "body":
                    output_namespace = grandchild.get("namespace")

    return WsdlBindingOperation(
        name=name,
        soap_action=soap_action,
        style=style,
        use=input_use,
        input_namespace=input_namespace,
        output_namespace=output_namespace,
    )


def _parse_service(elem: _Element) -> WsdlService:
    name = elem.get("name", "")
    ports: list[WsdlPort] = []
    for child in elem:
        if local_name(child) == "port":
            port_name = child.get("name", "")
            binding_ref = child.get("binding", "")
            binding = _local(binding_ref)
            address = ""
            for grandchild in child:
                if local_name(grandchild) == "address":
                    address = grandchild.get("location", "")
            ports.append(WsdlPort(name=port_name, binding=binding, address=address))
    return WsdlService(name=name, ports=ports)


# ---------------------------------------------------------------------------
# Schema type parsing
# ---------------------------------------------------------------------------

def _resolve_xsd_type(type_ref: str, nsmap: dict[str, str]) -> XsdType | str:
    """Resolve a type reference to an XsdType or return a string for lazy resolution."""
    resolved = xsd.resolve(type_ref)
    if resolved is not None:
        return resolved
    # Try stripping prefix
    bare = _local(type_ref)
    resolved = xsd.resolve(bare)
    if resolved is not None:
        return resolved
    # Return bare name for lazy resolution
    return bare


def _parse_schema_types(schema_elem: _Element, nsmap: dict[str, str]) -> dict[str, XsdType]:
    """Parse <xsd:schema> and return a dict of name → XsdType for complex types."""
    result: dict[str, XsdType] = {}

    for child in schema_elem:
        lname = local_name(child)
        if lname != "complexType":
            continue
        ct_name = child.get("name", "")
        if not ct_name:
            continue
        xsd_type = _parse_complex_type_element(ct_name, child, nsmap)
        if xsd_type is not None:
            result[ct_name] = xsd_type

    return result


def _parse_complex_type_element(
    name: str, elem: _Element, nsmap: dict[str, str]
) -> XsdType | None:
    """Parse a single <xsd:complexType> element."""
    for child in elem:
        lname = local_name(child)

        if lname == "sequence":
            fields: list[tuple[str, XsdType | str]] = []
            for sub in child:
                if local_name(sub) != "element":
                    continue
                field_name = sub.get("name", "")
                type_ref = sub.get("type", "xsd:string")
                max_occurs = sub.get("maxOccurs", "1")
                field_type: XsdType | str = _resolve_xsd_type(type_ref, nsmap)
                if max_occurs == "unbounded" or (max_occurs.isdigit() and int(max_occurs) > 1):
                    # Wrap in ArrayXsdType
                    if isinstance(field_type, XsdType):
                        base_type: XsdType = field_type
                    else:
                        base_type = xsd.resolve(field_type) or xsd.resolve("string")  # type: ignore[assignment]
                    field_type = ArrayXsdType(
                        name=f"{name}_{field_name}_array",
                        element_type=base_type,
                        element_tag=field_name,
                    )
                fields.append((field_name, field_type))
            return ComplexXsdType(name=name, fields=fields)

        if lname == "choice":
            options: list[tuple[str, XsdType]] = []
            for sub in child:
                if local_name(sub) != "element":
                    continue
                opt_name = sub.get("name", "")
                type_ref = sub.get("type", "xsd:string")
                opt_type_raw = _resolve_xsd_type(type_ref, nsmap)
                if isinstance(opt_type_raw, str):
                    opt_type_resolved: XsdType | None = (
                        xsd.resolve(opt_type_raw) or xsd.resolve("string")
                    )
                else:
                    opt_type_resolved = opt_type_raw
                if opt_type_resolved is None:
                    continue
                options.append((opt_name, opt_type_resolved))
            return ChoiceXsdType(name=name, options=options)

        if lname == "complexContent":
            # Check for soapenc:Array restriction
            for cc_child in child:
                if local_name(cc_child) == "restriction":
                    # Look for wsdl:arrayType attribute
                    array_type_attr = None
                    for attr_name, attr_val in cc_child.attrib.items():
                        if "arrayType" in attr_name or attr_name.endswith("}arrayType"):
                            array_type_attr = attr_val
                            break
                    if array_type_attr is None:
                        # Check children for wsdl:attribute
                        for attr_elem in cc_child:
                            if local_name(attr_elem) in ("attribute", "attributeGroup"):
                                wsdl_at = attr_elem.get(f"{{{NS.WSDL}}}arrayType")
                                if wsdl_at:
                                    array_type_attr = wsdl_at
                                    break
                    if array_type_attr is not None:
                        # Strip [] suffix if present
                        item_type_ref = array_type_attr.rstrip("[]").rstrip("[ ]")
                        item_type_raw2 = _resolve_xsd_type(item_type_ref, nsmap)
                        if isinstance(item_type_raw2, str):
                            item_type2: XsdType | None = (
                                xsd.resolve(item_type_raw2) or xsd.resolve("string")
                            )
                        else:
                            item_type2 = item_type_raw2
                        if item_type2 is not None:
                            return ArrayXsdType(
                                name=name, element_type=item_type2, element_tag="item"
                            )

    return None
