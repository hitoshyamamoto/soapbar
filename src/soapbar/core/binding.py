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
        self._check_required(sig.input_params, kwargs, "input")
        ns = sig.input_namespace or ""
        tag = f"{{{ns}}}{sig.name}" if ns else sig.name
        wrapper = sub_element(
            body_elem,
            tag,
            attrib={f"{{{NS.SOAP_ENC}}}encodingStyle": self._ENCODING},
            nsmap=self._wrapper_nsmap(),
        )
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        for param in sig.input_params:
            value = kwargs.get(param.name)
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                wrapper.append(param.xsd_type.to_element(param.name, value or {}, ""))
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
            attrib={f"{{{NS.SOAP_ENC}}}encodingStyle": self._ENCODING},
            nsmap=self._wrapper_nsmap(),
        )
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        for param in sig.output_params:
            value = values.get(param.name)
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                wrapper.append(param.xsd_type.to_element(param.name, value or {}, ""))
            else:
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
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        from soapbar.core.types import xsd as xsd_registry
        result: dict[str, Any] = {}
        for param in params:
            child = wrapper.find(param.name)
            if child is None:
                continue
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


class DocumentEncodedSerializer(BindingSerializer):
    """Document/Encoded: direct Body children with xsi:type, no operation wrapper."""

    def _nsmap(self) -> dict[str | None, str]:
        return {"xsi": NS.XSI, "xsd": NS.XSD}

    def serialize_request(
        self,
        sig: OperationSignature,
        kwargs: dict[str, Any],
        body_elem: _Element,
    ) -> None:
        self._check_required(sig.input_params, kwargs, "input")
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        for param in sig.input_params:
            value = kwargs.get(param.name)
            ns = param.namespace or sig.input_namespace or ""
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                body_elem.append(param.xsd_type.to_element(param.name, value or {}, ns))
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
        for param in sig.output_params:
            value = values.get(param.name)
            ns = param.namespace or sig.output_namespace or ""
            if isinstance(param.xsd_type, (ComplexXsdType, ArrayXsdType, ChoiceXsdType)):
                body_elem.append(param.xsd_type.to_element(param.name, value or {}, ns))
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
        return self._extract_params(sig.input_params, body_elem, sig.input_namespace or "")

    def deserialize_response(
        self,
        sig: OperationSignature,
        body_elem: _Element,
    ) -> dict[str, Any]:
        return self._extract_params(sig.output_params, body_elem, sig.output_namespace or "")

    def _extract_params(
        self,
        params: list[OperationParameter],
        body_elem: _Element,
        op_namespace: str = "",
    ) -> dict[str, Any]:
        from soapbar.core.types import ArrayXsdType, ChoiceXsdType, ComplexXsdType
        from soapbar.core.types import xsd as xsd_registry
        result: dict[str, Any] = {}
        for param in params:
            ns = param.namespace or op_namespace
            child = body_elem.find(f"{{{ns}}}{param.name}") if ns else body_elem.find(param.name)
            if child is None:
                continue
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
    BindingStyle.RPC_ENCODED: RpcEncodedSerializer(),
    BindingStyle.RPC_LITERAL: RpcLiteralSerializer(),
    BindingStyle.DOCUMENT_LITERAL: DocumentLiteralSerializer(),
    BindingStyle.DOCUMENT_LITERAL_WRAPPED: DocumentLiteralWrappedSerializer(),
    BindingStyle.DOCUMENT_ENCODED: DocumentEncodedSerializer(),
}


def get_serializer(style: BindingStyle) -> BindingSerializer:
    return _SERIALIZER_MAP[style]
