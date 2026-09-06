# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""soapbar — Python SOAP toolkit."""
from __future__ import annotations

try:
    from importlib.metadata import version as _version
    __version__: str = _version("soapbar")
    """The installed soapbar version, from package metadata."""
except Exception:
    __version__ = "unknown"

# Core
from soapbar.client.client import NonSoapResponseError, SoapClient

# Client
from soapbar.client.transport import HttpTransport, load_pkcs12
from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import (
    WSA_ANONYMOUS,
    WSA_NONE,
    SoapEnvelope,
    SoapHeaderBlock,
    SoapVersion,
    WsaHeaders,
)
from soapbar.core.exceptions import SoapbarError
from soapbar.core.fault import SoapFault
from soapbar.core.mtom import (
    MtomAttachment,
    MtomMessage,
    build_mtom,
    extract_xop_elements,
    parse_mtom,
)
from soapbar.core.namespaces import NS
from soapbar.core.types import (
    AnyXmlType,
    ArrayXsdType,
    ChoiceXsdType,
    ComplexXsdType,
    RawXmlType,
    XsdType,
    xsd,
)
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
from soapbar.core.wsdl.builder import build_wsdl, build_wsdl_string
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file
from soapbar.core.wssecurity import (
    SecurityValidationError,
    UsernameTokenCredential,
    UsernameTokenValidator,
    XmlSecurityError,
    build_binary_security_token,
    build_security_header,
    decrypt_body,
    encrypt_body,
    extract_certificate_from_security,
    sign_element_by_id,
    sign_envelope,
    sign_envelope_bsp,
    verify_envelope,
    verify_envelope_bsp,
)
from soapbar.core.xml import (
    BodyTooLargeError,
    local_name,
    namespace_uri,
    parse_xml,
    parse_xml_document,
    to_string,
)
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp

# Server
from soapbar.server.service import SoapService, soap_operation
from soapbar.server.wsgi import WsgiSoapApp

__all__ = [  # noqa: RUF022
    "__version__",
    # core
    "NS",
    "parse_xml",
    "parse_xml_document",
    "to_string",
    "local_name",
    "namespace_uri",
    "BodyTooLargeError",
    "xsd",
    "XsdType",
    "ComplexXsdType",
    "ArrayXsdType",
    "ChoiceXsdType",
    "AnyXmlType",
    "RawXmlType",
    "SoapbarError",
    "SoapFault",
    "BindingStyle",
    "OperationSignature",
    "OperationParameter",
    "get_serializer",
    "SoapEnvelope",
    "SoapHeaderBlock",
    "SoapVersion",
    "WsaHeaders",
    "WSA_ANONYMOUS",
    "WSA_NONE",
    "WsdlBinding",
    "WsdlBindingOperation",
    "WsdlDefinition",
    "WsdlMessage",
    "WsdlOperation",
    "WsdlOperationMessage",
    "WsdlPart",
    "WsdlPort",
    "WsdlPortType",
    "WsdlService",
    "parse_wsdl",
    "parse_wsdl_file",
    "build_wsdl",
    "build_wsdl_string",
    "MtomAttachment",
    "MtomMessage",
    "parse_mtom",
    "build_mtom",
    "extract_xop_elements",
    "UsernameTokenCredential",
    "UsernameTokenValidator",
    "SecurityValidationError",
    "build_binary_security_token",
    "build_security_header",
    "extract_certificate_from_security",
    "XmlSecurityError",
    "sign_element_by_id",
    "sign_envelope",
    "sign_envelope_bsp",
    "verify_envelope",
    "verify_envelope_bsp",
    "encrypt_body",
    "decrypt_body",
    # server
    "SoapService",
    "SoapApplication",
    "soap_operation",
    "AsgiSoapApp",
    "WsgiSoapApp",
    # client
    "HttpTransport",
    "SoapClient",
    "NonSoapResponseError",
    "load_pkcs12",
]


# ---------------------------------------------------------------------------
# Deprecated top-level aliases (STABILITY.md, "Deprecation policy").
# Each name keeps working via module __getattr__ (PEP 562) but emits a
# DeprecationWarning pointing at its canonical import path; removal comes no
# sooner than the next minor release.
# ---------------------------------------------------------------------------

_DEPRECATED: dict[str, tuple[str, str]] = {
    "SoapMethod": ("soapbar.server.service", "SoapMethod"),
    "WsaEndpointReference": ("soapbar.core.envelope", "WsaEndpointReference"),
    "build_fault": ("soapbar.core.envelope", "build_fault"),
    "build_request": ("soapbar.core.envelope", "build_request"),
    "build_response": ("soapbar.core.envelope", "build_response"),
    "build_wsa_response_headers": ("soapbar.core.envelope", "build_wsa_response_headers"),
    "http_headers": ("soapbar.core.envelope", "http_headers"),
    "build_wsdl_bytes": ("soapbar.core.wsdl.builder", "build_wsdl_bytes"),
    "to_bytes": ("soapbar.core.xml", "to_bytes"),
}


def __getattr__(name: str) -> object:
    target = _DEPRECATED.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    import warnings

    module_path, attr = target
    warnings.warn(
        f"soapbar.{name} is deprecated; import {attr} from {module_path} "
        f"instead. The top-level alias will be removed in a future minor "
        f"release.",
        DeprecationWarning,
        stacklevel=2,
    )
    return getattr(importlib.import_module(module_path), attr)


def __dir__() -> list[str]:
    return sorted(set(__all__) | set(_DEPRECATED))
