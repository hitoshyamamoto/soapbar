# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""SOAP service base class and decorator."""
from __future__ import annotations

import inspect
import types
import typing
from collections.abc import Callable
from typing import Any, Protocol

from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import SoapVersion
from soapbar.core.types import xsd


def _unwrap_optional(hint: Any) -> tuple[Any, bool]:
    """Unwrap Optional[X] / X | None → (X, True); return (hint, False) otherwise."""
    origin = typing.get_origin(hint)
    if origin is typing.Union or isinstance(hint, types.UnionType):
        args = [a for a in typing.get_args(hint) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return hint, False


class _SoapMethod(Protocol):
    """Protocol for methods decorated with @soap_operation."""
    __soap_operation__: OperationSignature

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


def soap_operation(
    name: str | None = None,
    input_params: list[OperationParameter] | None = None,
    output_params: list[OperationParameter] | None = None,
    soap_action: str | None = None,
    documentation: str = "",
    one_way: bool = False,
    emit_rpc_result: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that marks a method as a SOAP operation."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        op_name = name or func.__name__

        # Introspect type hints if params not provided
        nonlocal input_params, output_params
        if input_params is None:
            hints = typing.get_type_hints(func)
            # Exclude 'return' and 'self'
            params: list[OperationParameter] = []
            sig = inspect.signature(func)
            for param_name, _param in sig.parameters.items():
                if param_name == "self":
                    continue
                hint = hints.get(param_name)
                if hint is not None:
                    inner_hint, is_optional = _unwrap_optional(hint)
                    xsd_type = xsd.python_to_xsd(inner_hint)
                    if xsd_type is not None:
                        has_default = _param.default is not inspect.Parameter.empty
                        required = not (is_optional or has_default)
                        params.append(
                            OperationParameter(
                                name=param_name, xsd_type=xsd_type, required=required
                            )
                        )
            input_params = params

        if output_params is None:
            hints = typing.get_type_hints(func)
            ret = hints.get("return")
            if ret is not None and ret is not type(None):
                xsd_type = xsd.python_to_xsd(ret)
                if xsd_type is not None:
                    output_params = [OperationParameter(name="return", xsd_type=xsd_type)]
                else:
                    output_params = []
            else:
                output_params = []

        func.__soap_operation__ = OperationSignature(  # type: ignore[attr-defined]
            name=op_name,
            input_params=input_params,
            output_params=output_params,
            soap_action=soap_action or "",
            one_way=one_way,
            emit_rpc_result=emit_rpc_result,
        )
        func.__soap_documentation__ = documentation  # type: ignore[attr-defined]
        return func

    return decorator


class SoapService:
    __service_name__: str = ""
    __tns__: str = "http://example.com/soap"
    __binding_style__: BindingStyle = BindingStyle.DOCUMENT_LITERAL_WRAPPED
    __soap_version__: SoapVersion = SoapVersion.SOAP_11
    __port_name__: str = ""
    __service_url__: str = "http://localhost:8000/soap"

    def get_operations(self) -> dict[str, _SoapMethod]:
        """Return {operation_name: method} for all @soap_operation methods."""
        result: dict[str, _SoapMethod] = {}
        for attr_name in dir(self.__class__):
            if attr_name.startswith("_"):
                continue
            attr = getattr(self, attr_name, None)
            if callable(attr) and hasattr(attr, "__soap_operation__"):
                sig: OperationSignature = attr.__soap_operation__
                # Patch soap_action if auto-generate needed
                if not sig.soap_action:
                    sig.soap_action = f"{self.__tns__}/{sig.name}"
                result[sig.name] = attr
        return result

    def get_operation_signatures(self) -> dict[str, OperationSignature]:
        return {
            name: method.__soap_operation__
            for name, method in self.get_operations().items()
        }
