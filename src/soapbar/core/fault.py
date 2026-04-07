"""SOAP Fault exception and XML builders.

NOTE: This module must NOT import envelope.py to avoid circular imports.
Fault envelopes are built using raw XML utilities directly.
"""
from __future__ import annotations

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.xml import (
    local_name,
    make_element,
    namespace_uri,
    parse_xml_document,
    sub_element,
)

# Fault code mapping between SOAP 1.1 and 1.2
_11_TO_12: dict[str, str] = {
    "Client": "Sender",
    "Server": "Receiver",
}
_12_TO_11: dict[str, str] = {v: k for k, v in _11_TO_12.items()}


def build_upgrade_header_block() -> _Element:
    """Build a ``soap12:Upgrade`` header block listing supported envelope versions.

    Required in SOAP 1.2 ``VersionMismatch`` faults per [SOAP12-P1] §5.4.7 **MUST**.
    """
    elem = make_element(f"{{{NS.SOAP12_ENV}}}Upgrade")
    # SOAP 1.2 (preferred — listed first)
    se12 = sub_element(elem, f"{{{NS.SOAP12_ENV}}}SupportedEnvelope")
    se12.set("qname", "soap12:Envelope")
    # SOAP 1.1
    se11 = sub_element(
        elem,
        f"{{{NS.SOAP12_ENV}}}SupportedEnvelope",
        nsmap={"soapenv": NS.SOAP_ENV},
    )
    se11.set("qname", "soapenv:Envelope")
    return elem


def build_not_understood_header_block(clark_tag: str) -> _Element:
    """Build a ``soap12:NotUnderstood`` header block for the given header tag.

    Should be included in SOAP 1.2 ``MustUnderstand`` faults per [SOAP12-P1] §5.4.8 **SHOULD**.

    *clark_tag* is the Clark-notation tag of the unrecognised header element,
    e.g. ``{http://example.com/ns}MyHeader``.
    """
    if clark_tag.startswith("{"):
        close = clark_tag.index("}")
        ns = clark_tag[1:close]
        local = clark_tag[close + 1:]
        prefix = NS.prefix_for(ns) or "hdr"
        qname_str = f"{prefix}:{local}"
        nsmap_extra: dict[str | None, str] = {prefix: ns}
    else:
        qname_str = clark_tag
        nsmap_extra = {}
    return make_element(
        f"{{{NS.SOAP12_ENV}}}NotUnderstood",
        attrib={"qname": qname_str},
        nsmap=nsmap_extra,
    )


class SoapFault(Exception):  # noqa: N818
    def __init__(
        self,
        faultcode: str,
        faultstring: str,
        faultactor: str | None = None,
        detail: str | _Element | None = None,
        subcodes: list[tuple[str, str]] | None = None,
    ) -> None:
        super().__init__(faultstring)
        self.faultcode = faultcode
        self.faultstring = faultstring
        self.faultactor = faultactor
        self.detail = detail
        # Each subcode is (namespace_uri, localname) so the QName prefix can be
        # declared in the serialised XML per [SOAP12-P1] §5.4.6 MUST.
        self.subcodes: list[tuple[str, str]] = subcodes or []

    # ------------------------------------------------------------------
    # SOAP 1.1
    # ------------------------------------------------------------------

    def to_soap11_element(self) -> _Element:
        fault = make_element(
            f"{{{NS.SOAP_ENV}}}Fault",
            nsmap={"soapenv": NS.SOAP_ENV},
        )
        sub_element(fault, "faultcode", text=self.faultcode)
        sub_element(fault, "faultstring", text=self.faultstring)
        if self.faultactor:
            sub_element(fault, "faultactor", text=self.faultactor)
        if self.detail is not None:
            detail_elem = sub_element(fault, "detail")
            if isinstance(self.detail, str):
                detail_elem.text = self.detail
            else:
                detail_elem.append(self.detail)
        return fault

    def to_soap11_envelope(self) -> _Element:
        env = make_element(
            f"{{{NS.SOAP_ENV}}}Envelope",
            nsmap={"soapenv": NS.SOAP_ENV},
        )
        body = sub_element(env, f"{{{NS.SOAP_ENV}}}Body")
        body.append(self.to_soap11_element())
        return env

    # ------------------------------------------------------------------
    # SOAP 1.2
    # ------------------------------------------------------------------

    def to_soap12_element(self) -> _Element:
        fault = make_element(
            f"{{{NS.SOAP12_ENV}}}Fault",
            nsmap={"soap12": NS.SOAP12_ENV},
        )
        # Code / Value
        code_elem = sub_element(fault, f"{{{NS.SOAP12_ENV}}}Code")
        # Map 1.1 codes to 1.2
        code_value = _11_TO_12.get(self.faultcode, self.faultcode)
        sub_element(code_elem, f"{{{NS.SOAP12_ENV}}}Value", text=f"soap12:{code_value}")
        # Subcodes — each (ns, local) rendered as a namespace-qualified QName
        # so the prefix is declared in-scope per [SOAP12-P1] §5.4.6 MUST.
        if self.subcodes:
            parent = code_elem
            for i, (ns, local) in enumerate(self.subcodes):
                prefix = NS.prefix_for(ns) or f"sc{i}"
                subcode_elem = sub_element(parent, f"{{{NS.SOAP12_ENV}}}Subcode")
                sub_element(
                    subcode_elem,
                    f"{{{NS.SOAP12_ENV}}}Value",
                    text=f"{prefix}:{local}",
                    nsmap={prefix: ns},
                )
                parent = subcode_elem
        # Reason
        reason_elem = sub_element(fault, f"{{{NS.SOAP12_ENV}}}Reason")
        sub_element(
            reason_elem,
            f"{{{NS.SOAP12_ENV}}}Text",
            attrib={"{http://www.w3.org/XML/1998/namespace}lang": "en"},
            text=self.faultstring,
        )
        # Role (faultactor equivalent)
        if self.faultactor:
            sub_element(fault, f"{{{NS.SOAP12_ENV}}}Role", text=self.faultactor)
        # Detail
        if self.detail is not None:
            detail_elem = sub_element(fault, f"{{{NS.SOAP12_ENV}}}Detail")
            if isinstance(self.detail, str):
                detail_elem.text = self.detail
            else:
                detail_elem.append(self.detail)
        return fault

    def to_soap12_envelope(
        self,
        header_blocks: list[_Element] | None = None,
    ) -> _Element:
        env = make_element(
            f"{{{NS.SOAP12_ENV}}}Envelope",
            nsmap={"soap12": NS.SOAP12_ENV},
        )
        if header_blocks:
            header = sub_element(env, f"{{{NS.SOAP12_ENV}}}Header")
            for block in header_blocks:
                header.append(block)
        body = sub_element(env, f"{{{NS.SOAP12_ENV}}}Body")
        body.append(self.to_soap12_element())
        return env

    # ------------------------------------------------------------------
    # Parse from element
    # ------------------------------------------------------------------

    @classmethod
    def from_element(cls, elem: _Element) -> SoapFault:
        """Parse a Fault from a Fault element or an Envelope element."""
        root = parse_xml_document(elem)
        ns = namespace_uri(root)
        lname = local_name(root)

        if lname == "Envelope":
            # Find the Fault inside Body
            if ns == NS.SOAP_ENV:
                body = root.find(f"{{{NS.SOAP_ENV}}}Body")
                if body is not None:
                    fault_elem = body.find(f"{{{NS.SOAP_ENV}}}Fault")
                    if fault_elem is not None:
                        return cls._parse_11(fault_elem)
            elif ns == NS.SOAP12_ENV:
                body = root.find(f"{{{NS.SOAP12_ENV}}}Body")
                if body is not None:
                    fault_elem = body.find(f"{{{NS.SOAP12_ENV}}}Fault")
                    if fault_elem is not None:
                        return cls._parse_12(fault_elem)
            raise ValueError("No Fault element found in Envelope")
        elif lname == "Fault":
            if ns == NS.SOAP_ENV:
                return cls._parse_11(root)
            elif ns == NS.SOAP12_ENV:
                return cls._parse_12(root)
        raise ValueError(f"Cannot parse fault from element: {root.tag!r}")

    @classmethod
    def _parse_11(cls, fault_elem: _Element) -> SoapFault:
        fc_elem = fault_elem.find("faultcode")
        fs_elem = fault_elem.find("faultstring")
        fa_elem = fault_elem.find("faultactor")
        det_elem = fault_elem.find("detail")

        faultcode = fc_elem.text or "" if fc_elem is not None else "Server"
        faultstring = fs_elem.text or "" if fs_elem is not None else ""
        faultactor = fa_elem.text if fa_elem is not None else None

        detail: str | _Element | None = None
        if det_elem is not None:
            children = list(det_elem)
            detail = children[0] if children else det_elem.text

        return cls(faultcode, faultstring, faultactor=faultactor, detail=detail)

    @classmethod
    def _parse_12(cls, fault_elem: _Element) -> SoapFault:
        code_elem = fault_elem.find(f"{{{NS.SOAP12_ENV}}}Code")
        reason_elem = fault_elem.find(f"{{{NS.SOAP12_ENV}}}Reason")
        role_elem = fault_elem.find(f"{{{NS.SOAP12_ENV}}}Role")
        det_elem = fault_elem.find(f"{{{NS.SOAP12_ENV}}}Detail")

        faultcode = ""
        if code_elem is not None:
            val_elem = code_elem.find(f"{{{NS.SOAP12_ENV}}}Value")
            if val_elem is not None and val_elem.text:
                raw = val_elem.text.split(":")[-1]
                # Map 1.2 codes back to 1.1 canonical
                faultcode = _12_TO_11.get(raw, raw)

        faultstring = ""
        if reason_elem is not None:
            text_elem = reason_elem.find(f"{{{NS.SOAP12_ENV}}}Text")
            if text_elem is not None:
                faultstring = text_elem.text or ""

        faultactor = role_elem.text if role_elem is not None else None

        detail: str | _Element | None = None
        if det_elem is not None:
            children = list(det_elem)
            detail = children[0] if children else det_elem.text

        return cls(faultcode, faultstring, faultactor=faultactor, detail=detail)

    def __repr__(self) -> str:
        return f"SoapFault({self.faultcode!r}, {self.faultstring!r})"
