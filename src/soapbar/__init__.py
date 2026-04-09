"""soapbar — Python SOAP toolkit."""
from __future__ import annotations

__version__ = "0.1.0"

# Core
from soapbar.client.client import SoapClient

# Client
from soapbar.client.transport import HttpTransport
from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    get_serializer,
)
from soapbar.core.envelope import (
    SoapEnvelope,
    SoapHeaderBlock,
    SoapVersion,
    WsaEndpointReference,
    WsaHeaders,
    build_fault,
    build_request,
    build_response,
    build_wsa_response_headers,
    http_headers,
)
from soapbar.core.fault import SoapFault
from soapbar.core.mtom import MtomAttachment, MtomMessage, build_mtom, parse_mtom
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
from soapbar.core.wsdl.builder import build_wsdl, build_wsdl_bytes, build_wsdl_string
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
    sign_envelope,
    sign_envelope_bsp,
    verify_envelope,
    verify_envelope_bsp,
)
from soapbar.core.xml import parse_xml, parse_xml_document, to_bytes, to_string
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
    "to_bytes",
    "xsd",
    "XsdType",
    "ComplexXsdType",
    "ArrayXsdType",
    "ChoiceXsdType",
    "SoapFault",
    "BindingStyle",
    "OperationSignature",
    "OperationParameter",
    "get_serializer",
    "SoapEnvelope",
    "SoapHeaderBlock",
    "SoapVersion",
    "WsaHeaders",
    "WsaEndpointReference",
    "build_request",
    "build_response",
    "build_fault",
    "build_wsa_response_headers",
    "http_headers",
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
    "build_wsdl_bytes",
    "MtomAttachment",
    "MtomMessage",
    "parse_mtom",
    "build_mtom",
    "UsernameTokenCredential",
    "UsernameTokenValidator",
    "SecurityValidationError",
    "build_binary_security_token",
    "build_security_header",
    "extract_certificate_from_security",
    "XmlSecurityError",
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
]
