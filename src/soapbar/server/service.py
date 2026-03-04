"""SOAP service base class and decorator."""
from __future__ import annotations

import typing
from collections.abc import Callable
from typing import Any

from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import SoapVersion
from soapbar.core.types import xsd


def soap_operation(
    name: str | None = None,
    input_params: list[OperationParameter] | None = None,
    output_params: list[OperationParameter] | None = None,
    soap_action: str | None = None,
    documentation: str = "",
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
            import inspect
            sig = inspect.signature(func)
            for param_name, _param in sig.parameters.items():
                if param_name == "self":
                    continue
                hint = hints.get(param_name)
                if hint is not None:
                    xsd_type = xsd.python_to_xsd(hint)
                    if xsd_type is not None:
                        params.append(OperationParameter(name=param_name, xsd_type=xsd_type))
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

    def get_operations(self) -> dict[str, Callable[..., Any]]:
        """Return {operation_name: method} for all @soap_operation methods."""
        result: dict[str, Callable[..., Any]] = {}
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
