"""SOAP binding styles and serializers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from lxml.etree import _Element  # noqa: PLC2701

from soapbar.core.namespaces import NS
from soapbar.core.types import XsdType
from soapbar.core.xml import local_name, sub_element


class BindingStyle(Enum):
    RPC_ENCODED = "rpc_encoded"
    RPC_LITERAL = "rpc_literal"
    DOCUMENT_LITERAL = "document_literal"
    DOCUMENT_LITERAL_WRAPPED = "document_literal_wrapped"

    @property
    def soap_style(self) -> str:
        return "rpc" if self in (BindingStyle.RPC_ENCODED, BindingStyle.RPC_LITERAL) else "document"

    @property
    def soap_use(self) -> str:
        return "encoded" if self == BindingStyle.RPC_ENCODED else "literal"

    @property
    def is_rpc(self) -> bool:
        return self.soap_style == "rpc"

    @property
    def is_encoded(self) -> bool:
        return self == BindingStyle.RPC_ENCODED

    @property
    def is_wrapped(self) -> bool:
        return self == BindingStyle.DOCUMENT_LITERAL_WRAPPED


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


class BindingSerializer(ABC):
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

    _ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"

    def _wrapper_nsmap(self) -> dict[str | None, str]:
        return {
            "soapenc": NS.SOAP_ENC,
            "xsi": NS.XSI,
            "xsd": NS.XSD,
        }

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(
            body_elem,
            tag,
            attrib={f"{{{NS.SOAP_ENC}}}encodingStyle": self._ENCODING},
            nsmap=self._wrapper_nsmap(),
        )
        for param in sig.input_params:
            value = kwargs.get(param.name)
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
        ns = sig.output_namespace or ""
        tag = f"{{{ns}}}{sig.name}Response" if ns else f"{sig.name}Response"
        wrapper = sub_element(
            body_elem,
            tag,
            attrib={f"{{{NS.SOAP_ENC}}}encodingStyle": self._ENCODING},
            nsmap=self._wrapper_nsmap(),
        )
        for param in sig.output_params:
            value = values.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            sub_element(
                wrapper,
                param.name,
                attrib={f"{{{NS.XSI}}}type": f"xsd:{param.xsd_type.name}"},
                text=text,
            )

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
        from soapbar.core.types import xsd as xsd_registry
        result: dict[str, Any] = {}
        for param in params:
            child = wrapper.find(param.name)
            if child is None:
                continue
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
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(body_elem, tag)
        for param in sig.input_params:
            value = kwargs.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            sub_element(wrapper, param.name, text=text)

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        ns = sig.output_namespace or ""
        tag = f"{{{ns}}}{sig.name}Response" if ns else f"{sig.name}Response"
        wrapper = sub_element(body_elem, tag)
        for param in sig.output_params:
            value = values.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            sub_element(wrapper, param.name, text=text)

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
                result[param.name] = param.xsd_type.from_xml(child.text or "")
        return result


class DocumentLiteralSerializer(BindingSerializer):
    """Document/Literal: params are direct Body children."""

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        if len(sig.input_params) == 1:
            param = sig.input_params[0]
            value = kwargs.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            ns = param.namespace or sig.input_namespace or ""
            tag = f"{{{ns}}}{param.name}" if ns else param.name
            sub_element(body_elem, tag, text=text)
        else:
            parts = sub_element(body_elem, "_parts")
            for param in sig.input_params:
                value = kwargs.get(param.name)
                text = param.xsd_type.to_xml(value) if value is not None else ""
                sub_element(parts, param.name, text=text)

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        if len(sig.output_params) == 1:
            param = sig.output_params[0]
            value = values.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            ns = param.namespace or sig.output_namespace or ""
            tag = f"{{{ns}}}{param.name}" if ns else param.name
            sub_element(body_elem, tag, text=text)
        else:
            parts = sub_element(body_elem, "_parts")
            for param in sig.output_params:
                value = values.get(param.name)
                text = param.xsd_type.to_xml(value) if value is not None else ""
                sub_element(parts, param.name, text=text)

    def deserialize_request(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        return self._extract(sig.input_params, body_elem)

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        return self._extract(sig.output_params, body_elem)

    def _extract(
        self,
        params: list[OperationParameter],
        body_elem: _Element,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        children = list(body_elem)
        if not children:
            return result
        # If single child is _parts wrapper
        if len(children) == 1 and local_name(children[0]) == "_parts":
            container = children[0]
        else:
            container = body_elem
        for param in params:
            # Try with namespace
            ns = param.namespace or ""
            child = container.find(f"{{{ns}}}{param.name}") if ns else container.find(param.name)
            if child is None:
                child = container.find(param.name)
            if child is not None:
                result[param.name] = param.xsd_type.from_xml(child.text or "")
        return result


class DocumentLiteralWrappedSerializer(BindingSerializer):
    """Document/Literal/Wrapped: single wrapper element named after operation."""

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(body_elem, tag)
        for param in sig.input_params:
            value = kwargs.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            sub_element(wrapper, param.name, text=text)

    def serialize_response(
        self,
        sig: OperationSignature,
        values: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        ns = sig.output_namespace or ""
        tag = f"{{{ns}}}{sig.name}Response" if ns else f"{sig.name}Response"
        wrapper = sub_element(body_elem, tag)
        for param in sig.output_params:
            value = values.get(param.name)
            text = param.xsd_type.to_xml(value) if value is not None else ""
            sub_element(wrapper, param.name, text=text)

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
                result[param.name] = param.xsd_type.from_xml(child.text or "")
        return result


_SERIALIZER_MAP: dict[BindingStyle, BindingSerializer] = {
    BindingStyle.RPC_ENCODED: RpcEncodedSerializer(),
    BindingStyle.RPC_LITERAL: RpcLiteralSerializer(),
    BindingStyle.DOCUMENT_LITERAL: DocumentLiteralSerializer(),
    BindingStyle.DOCUMENT_LITERAL_WRAPPED: DocumentLiteralWrappedSerializer(),
}


def get_serializer(style: BindingStyle) -> BindingSerializer:
    return _SERIALIZER_MAP[style]
