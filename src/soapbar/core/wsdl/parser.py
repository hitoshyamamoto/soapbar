"""WSDL parser — supports SOAP 1.1 and SOAP 1.2 binding extensions."""
from __future__ import annotations

from pathlib import Path

from lxml.etree import _Element  # noqa: PLC2701

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


def parse_wsdl(source: str | bytes | Path | _Element) -> WsdlDefinition:
    root = parse_xml_document(source)
    nsmap: dict[str, str] = {k: v for k, v in root.nsmap.items() if k is not None}

    defn = WsdlDefinition(
        name=root.get("name", ""),
        target_namespace=root.get("targetNamespace", ""),
    )

    for child in root:
        lname = local_name(child)

        if lname == "import":
            raise NotImplementedError(
                "WSDL <import> is not supported. Inline all definitions before parsing."
            )

        elif lname == "types":
            defn.schema_elements = list(child)

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
    return parse_wsdl(Path(path))


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
