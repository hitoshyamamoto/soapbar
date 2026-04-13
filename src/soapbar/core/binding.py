# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""SOAP binding styles and serializers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.types import XsdType
from soapbar.core.xml import sub_element


class BindingStyle(Enum):
    RPC_ENCODED = "rpc_encoded"
    RPC_LITERAL = "rpc_literal"
    DOCUMENT_LITERAL = "document_literal"
    DOCUMENT_LITERAL_WRAPPED = "document_literal_wrapped"
    DOCUMENT_ENCODED = "document_encoded"

    @property
    def soap_style(self) -> str:
        return "rpc" if self in (BindingStyle.RPC_ENCODED, BindingStyle.RPC_LITERAL) else "document"

    @property
    def soap_use(self) -> str:
        encoded = (BindingStyle.RPC_ENCODED, BindingStyle.DOCUMENT_ENCODED)
        return "encoded" if self in encoded else "literal"

    @property
    def is_rpc(self) -> bool:
        return self.soap_style == "rpc"

    @property
    def is_encoded(self) -> bool:
        return self in (BindingStyle.RPC_ENCODED, BindingStyle.DOCUMENT_ENCODED)

    @property
    def is_wrapped(self) -> bool:
        return self == BindingStyle.DOCUMENT_LITERAL_WRAPPED

    @property
    def is_wsi_conformant(self) -> bool:
        """Return False for styles that violate WS-I Basic Profile 1.1 R2706.

        ``RPC_ENCODED`` and ``DOCUMENT_ENCODED`` use SOAP Section 5 encoding,
        which WS-I BP 1.1 R2706 prohibits.  Use them only for WITSML or other
        legacy protocols that explicitly require Section 5 encoding.
        """
        return self not in (BindingStyle.RPC_ENCODED, BindingStyle.DOCUMENT_ENCODED)


@dataclass
class OperationParameter:
    name: str
    xsd_type: XsdType
    required: bool = True
    namespace: str | None = None


@dataclass
class OperationSignature:
    name: str
    input_params: list[OperationParameter] = field(default_factory=list)
    output_params: list[OperationParameter] = field(default_factory=list)
    soap_action: str = ""
    input_namespace: str | None = None
    output_namespace: str | None = None
    one_way: bool = False  # G08: HTTP 202 / SOAP 1.2 P2 §7.5.1 one-way MEP
    emit_rpc_result: bool = False  # G10: rpc:result SHOULD per SOAP 1.2 P2 §4.2.1


class BindingSerializer(ABC):
    @staticmethod
    def _check_required(
        params: list[OperationParameter], values: dict[str, Any], direction: str
    ) -> None:
        missing = [p.name for p in params if p.required and values.get(p.name) is None]
        if missing:
            from soapbar.core.fault import SoapFault
            fault_code = "Server" if direction == "output" else "Client"
            msg = f"Missing required {direction} parameter(s): {', '.join(missing)}"
            raise SoapFault(fault_code, msg)

    @staticmethod
    def _serialize_param_value(
        parent: _Element, tag: str, ns: str, param: OperationParameter, value: Any
    ) -> None:
        """Serialize a single parameter to an XML element under parent."""
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
            parent.append(param.xsd_type.to_element(tag, value or {}, ns))
        else:
            text = param.xsd_type.to_xml(value) if value is not None else ""
            full_tag = f"{{{ns}}}{tag}" if ns else tag
            sub_element(parent, full_tag, text=text)

    @staticmethod
    def _deserialize_param_value(child: _Element, param: OperationParameter) -> Any:
        """Deserialize a single parameter from an XML element."""
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
            return param.xsd_type.from_element(child)
        return param.xsd_type.from_xml(child.text or "")

    @abstractmethod
    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None: ...

    @abstractmethod
    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None: ...

    @abstractmethod
    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]: ...

    @abstractmethod
    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]: ...


class RpcEncodedSerializer(BindingSerializer):
    """RPC/Encoded: wrapper element with xsi:type on each param."""

    def __init__(self, soap_enc_ns: str = NS.SOAP_ENC) -> None:
        self.soap_enc_ns = soap_enc_ns

    def _wrapper_nsmap(self) -> dict[str | None, str]:
        return {
            "soapenc": self.soap_enc_ns,
            "xsi": NS.XSI,
            "xsd": NS.XSD,
        }

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.input_params, kwargs, "input")
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(
            body_elem,
            tag,
            attrib={f"{{{self.soap_enc_ns}}}encodingStyle": self.soap_enc_ns},
            nsmap=self._wrapper_nsmap(),
        )
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        ref_map = self._collect_shared_ids(kwargs)
        seen: set[int] = set()
        for param in sig.input_params:
            value = kwargs.get(param.name)
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                se = self._soap_enc_ns_for_type(param.xsd_type)
                elem = param.xsd_type.to_element(param.name, value or {}, "", soap_encoding=se)
                self._apply_multiref(elem, value, ref_map, seen, wrapper)
                wrapper.append(elem)
            else:
                text = param.xsd_type.to_xml(value) if value is not None else ""
                sub_element(
                    wrapper,
                    param.name,
                    attrib={f"{{{NS.XSI}}}type": f"xsd:{param.xsd_type.name}"},
                    text=text,
                )

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.output_params, values, "output")
        ns = sig.output_namespace or ""
        tag = f"{{{ns}}}{sig.name}Response" if ns else f"{sig.name}Response"
        wrapper = sub_element(
            body_elem,
            tag,
            attrib={f"{{{self.soap_enc_ns}}}encodingStyle": self.soap_enc_ns},
            nsmap=self._wrapper_nsmap(),
        )
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        ref_map = self._collect_shared_ids(values)
        seen: set[int] = set()
        for param in sig.output_params:
            value = values.get(param.name)
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                se = self._soap_enc_ns_for_type(param.xsd_type)
                elem = param.xsd_type.to_element(param.name, value or {}, "", soap_encoding=se)
                self._apply_multiref(elem, value, ref_map, seen, wrapper)
                wrapper.append(elem)
            else:
                text = param.xsd_type.to_xml(value) if value is not None else ""
                sub_element(
                    wrapper,
                    param.name,
                    attrib={f"{{{NS.XSI}}}type": f"xsd:{param.xsd_type.name}"},
                    text=text,
                )

    # ------------------------------------------------------------------
    # G06 — multi-reference href/id helpers (SOAP 1.1 §5.2.5)
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_shared_ids(values: dict[str, Any]) -> dict[int, str]:
        """Return {id(obj): refN} for complex objects that appear >1 time."""
        counts: dict[int, int] = {}
        for v in values.values():
            if isinstance(v, (dict, list)) and v is not None:
                counts[id(v)] = counts.get(id(v), 0) + 1
        ref_map: dict[int, str] = {}
        n = 0
        for obj_id, count in counts.items():
            if count > 1:
                n += 1
                ref_map[obj_id] = f"ref-{n}"
        return ref_map

    @staticmethod
    def _apply_multiref(
        elem: _Element,
        value: Any,
        ref_map: dict[int, str],
        seen: set[int],
        siblings: _Element,
    ) -> None:
        """If *value* is a shared object, tag *elem* with id= (first time) or
        replace its children/text with href= (subsequent times)."""
        if not isinstance(value, (dict, list)):
            return
        obj_id = id(value)
        if obj_id not in ref_map:
            return
        ref_id = ref_map[obj_id]
        if obj_id not in seen:
            seen.add(obj_id)
            elem.set("id", ref_id)
        else:
            # Subsequent reference: clear content and emit href
            for child in list(elem):
                elem.remove(child)
            elem.text = None
            elem.set("href", f"#{ref_id}")

    @staticmethod
    def _build_id_map(root: _Element) -> dict[str, _Element]:
        """Collect all elements with id= in the subtree."""
        result: dict[str, _Element] = {}
        for elem in root.iter():
            eid = elem.get("id")
            if eid is not None:
                result[eid] = elem
        return result

    def _soap_enc_ns_for_type(self, xsd_type: Any) -> str | None:
        """Return encoding NS for array types, None for others."""
        from soapbar.core.types import ArrayXsdType
        return self.soap_enc_ns if isinstance(xsd_type, ArrayXsdType) else None

    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        wrapper = body_elem[0] if len(body_elem) else body_elem
        id_map = self._build_id_map(body_elem)
        return self._extract_params(sig.input_params, wrapper, id_map)

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        wrapper = body_elem[0] if len(body_elem) else body_elem
        id_map = self._build_id_map(body_elem)
        return self._extract_params(sig.output_params, wrapper, id_map)

    def _extract_params(
        self,
        params: list[OperationParameter],
        wrapper: _Element,
        id_map: dict[str, _Element] | None = None,
    ) -> dict[str, Any]:
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        from soapbar.core.types import xsd as xsd_registry
        id_map = id_map or {}
        result: dict[str, Any] = {}
        for param in params:
            child = wrapper.find(param.name)
            if child is None:
                continue
            # G06: resolve href references
            href = child.get("href")
            if href and href.startswith("#"):
                resolved = id_map.get(href[1:])
                if resolved is not None:
                    child = resolved
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                result[param.name] = param.xsd_type.from_element(child)
            else:
                # Prefer xsi:type for type resolution
                xsi_type = child.get(f"{{{NS.XSI}}}type")
                xsd_type = xsd_registry.resolve(xsi_type) if xsi_type else param.xsd_type
                if xsd_type is None:
                    xsd_type = param.xsd_type
                result[param.name] = xsd_type.from_xml(child.text or "")
        return result


class RpcLiteralSerializer(BindingSerializer):
    """RPC/Literal: same structure as RPC/Encoded but no xsi:type or encodingStyle."""

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.input_params, kwargs, "input")
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(body_elem, tag)
        for param in sig.input_params:
            value = kwargs.get(param.name)
            self._serialize_param_value(wrapper, param.name, "", param, value)

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.output_params, values, "output")
        ns = sig.output_namespace or ""
        tag = f"{{{ns}}}{sig.name}Response" if ns else f"{sig.name}Response"
        wrapper = sub_element(body_elem, tag)
        # G10: rpc:result per SOAP 1.2 Part 2 §4.2.1 (SHOULD, not MUST).
        # Only emitted when sig.emit_rpc_result is True (opt-in) to avoid
        # breaking strict-mode clients (e.g. zeep) that reject undeclared elements.
        if sig.emit_rpc_result and sig.output_params:
            sub_element(
                wrapper,
                f"{{{NS.SOAP_RPC}}}result",
                nsmap={"rpc": NS.SOAP_RPC},
                text=sig.output_params[0].name,
            )
        for param in sig.output_params:
            value = values.get(param.name)
            self._serialize_param_value(wrapper, param.name, "", param, value)

    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        wrapper = body_elem[0] if len(body_elem) else body_elem
        return self._extract_params(sig.input_params, wrapper)

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        wrapper = body_elem[0] if len(body_elem) else body_elem
        return self._extract_params(sig.output_params, wrapper)

    def _extract_params(
        self,
        params: list[OperationParameter],
        wrapper: _Element,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for param in params:
            child = wrapper.find(param.name)
            if child is not None:
                result[param.name] = self._deserialize_param_value(child, param)
        return result


class DocumentLiteralSerializer(BindingSerializer):
    """Document/Literal: params are direct Body children."""

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.input_params, kwargs, "input")
        for param in sig.input_params:
            value = kwargs.get(param.name)
            ns = param.namespace or sig.input_namespace or ""
            self._serialize_param_value(body_elem, param.name, ns, param, value)

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.output_params, values, "output")
        for param in sig.output_params:
            value = values.get(param.name)
            ns = param.namespace or sig.output_namespace or ""
            self._serialize_param_value(body_elem, param.name, ns, param, value)

    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        return self._extract(sig.input_params, body_elem, sig.input_namespace or "")

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        return self._extract(sig.output_params, body_elem, sig.output_namespace or "")

    def _extract(
        self,
        params: list[OperationParameter],
        body_elem: _Element,
        op_namespace: str = "",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for param in params:
            ns = param.namespace or op_namespace
            child = body_elem.find(f"{{{ns}}}{param.name}") if ns else body_elem.find(param.name)
            if child is not None:
                result[param.name] = self._deserialize_param_value(child, param)
        return result


class DocumentLiteralWrappedSerializer(BindingSerializer):
    """Document/Literal/Wrapped: single wrapper element named after operation."""

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.input_params, kwargs, "input")
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(body_elem, tag)
        for param in sig.input_params:
            value = kwargs.get(param.name)
            child_ns = param.namespace or sig.input_namespace or ""
            self._serialize_param_value(wrapper, param.name, child_ns, param, value)

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.output_params, values, "output")
        ns = sig.output_namespace or ""
        tag = f"{{{ns}}}{sig.name}Response" if ns else f"{sig.name}Response"
        wrapper = sub_element(body_elem, tag)
        for param in sig.output_params:
            value = values.get(param.name)
            child_ns = param.namespace or sig.output_namespace or ""
            self._serialize_param_value(wrapper, param.name, child_ns, param, value)

    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        wrapper = body_elem[0] if len(body_elem) else body_elem
        return self._extract_params(sig.input_params, wrapper, sig.input_namespace or "")

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        wrapper = body_elem[0] if len(body_elem) else body_elem
        return self._extract_params(sig.output_params, wrapper, sig.output_namespace or "")

    def _extract_params(
        self,
        params: list[OperationParameter],
        wrapper: _Element,
        op_namespace: str = "",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for param in params:
            ns = param.namespace or op_namespace
            # Accept qualified (elementFormDefault=qualified) children first,
            # falling back to unqualified for tolerance.
            child = wrapper.find(f"{{{ns}}}{param.name}") if ns else None
            if child is None:
                child = wrapper.find(param.name)
            if child is not None:
                result[param.name] = self._deserialize_param_value(child, param)
        return result


class DocumentEncodedSerializer(BindingSerializer):
    """Document/Encoded: direct Body children with xsi:type, no operation wrapper."""

    def __init__(self, soap_enc_ns: str = NS.SOAP_ENC) -> None:
        self.soap_enc_ns = soap_enc_ns

    def _nsmap(self) -> dict[str | None, str]:
        return {"xsi": NS.XSI, "xsd": NS.XSD}

    def _soap_enc_ns_for_type(self, xsd_type: Any) -> str | None:
        from soapbar.core.types import ArrayXsdType
        return self.soap_enc_ns if isinstance(xsd_type, ArrayXsdType) else None

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.input_params, kwargs, "input")
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        ref_map = RpcEncodedSerializer._collect_shared_ids(kwargs)
        seen: set[int] = set()
        for param in sig.input_params:
            value = kwargs.get(param.name)
            ns = param.namespace or sig.input_namespace or ""
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                se = self._soap_enc_ns_for_type(param.xsd_type)
                elem = param.xsd_type.to_element(param.name, value or {}, ns, soap_encoding=se)
                RpcEncodedSerializer._apply_multiref(elem, value, ref_map, seen, body_elem)
                body_elem.append(elem)
            else:
                text = param.xsd_type.to_xml(value) if value is not None else ""
                tag = f"{{{ns}}}{param.name}" if ns else param.name
                sub_element(
                    body_elem,
                    tag,
                    attrib={f"{{{NS.XSI}}}type": f"xsd:{param.xsd_type.name}"},
                    nsmap=self._nsmap(),
                    text=text,
                )

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.output_params, values, "output")
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        ref_map = RpcEncodedSerializer._collect_shared_ids(values)
        seen: set[int] = set()
        for param in sig.output_params:
            value = values.get(param.name)
            ns = param.namespace or sig.output_namespace or ""
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                se = self._soap_enc_ns_for_type(param.xsd_type)
                elem = param.xsd_type.to_element(param.name, value or {}, ns, soap_encoding=se)
                RpcEncodedSerializer._apply_multiref(elem, value, ref_map, seen, body_elem)
                body_elem.append(elem)
            else:
                text = param.xsd_type.to_xml(value) if value is not None else ""
                tag = f"{{{ns}}}{param.name}" if ns else param.name
                sub_element(
                    body_elem,
                    tag,
                    attrib={f"{{{NS.XSI}}}type": f"xsd:{param.xsd_type.name}"},
                    nsmap=self._nsmap(),
                    text=text,
                )

    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        id_map = RpcEncodedSerializer._build_id_map(body_elem)
        return self._extract_params(sig.input_params, body_elem, sig.input_namespace or "", id_map)

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        id_map = RpcEncodedSerializer._build_id_map(body_elem)
        return self._extract_params(
            sig.output_params, body_elem, sig.output_namespace or "", id_map
        )

    def _extract_params(
        self,
        params: list[OperationParameter],
        body_elem: _Element,
        op_namespace: str = "",
        id_map: dict[str, _Element] | None = None,
    ) -> dict[str, Any]:
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        from soapbar.core.types import xsd as xsd_registry
        id_map = id_map or {}
        result: dict[str, Any] = {}
        for param in params:
            ns = param.namespace or op_namespace
            child = body_elem.find(f"{{{ns}}}{param.name}") if ns else body_elem.find(param.name)
            if child is None:
                continue
            # G06: resolve href references
            href = child.get("href")
            if href and href.startswith("#"):
                resolved = id_map.get(href[1:])
                if resolved is not None:
                    child = resolved
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                result[param.name] = param.xsd_type.from_element(child)
            else:
                xsi_type = child.get(f"{{{NS.XSI}}}type")
                xsd_type = xsd_registry.resolve(xsi_type) if xsi_type else param.xsd_type
                if xsd_type is None:
                    xsd_type = param.xsd_type
                result[param.name] = xsd_type.from_xml(child.text or "")
        return result


_SERIALIZER_MAP: dict[BindingStyle, BindingSerializer] = {
    BindingStyle.RPC_LITERAL: RpcLiteralSerializer(),
    BindingStyle.DOCUMENT_LITERAL: DocumentLiteralSerializer(),
    BindingStyle.DOCUMENT_LITERAL_WRAPPED: DocumentLiteralWrappedSerializer(),
}


def get_serializer(style: BindingStyle, soap_version: Any = None) -> BindingSerializer:
    """Return a serializer for *style*.

    For encoded styles (G05), pass *soap_version* (a ``SoapVersion`` enum value)
    so the serializer can emit the correct array attributes for SOAP 1.1 vs 1.2.
    """
    if style in (BindingStyle.RPC_ENCODED, BindingStyle.DOCUMENT_ENCODED):
        from soapbar.core.envelope import SoapVersion
        enc_ns = NS.SOAP12_ENC if soap_version == SoapVersion.SOAP_12 else NS.SOAP_ENC
        if style == BindingStyle.RPC_ENCODED:
            return RpcEncodedSerializer(soap_enc_ns=enc_ns)
        return DocumentEncodedSerializer(soap_enc_ns=enc_ns)
    return _SERIALIZER_MAP[style]
