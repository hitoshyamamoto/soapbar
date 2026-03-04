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
    SoapVersion,
    build_fault,
    build_request,
    build_response,
    http_headers,
)
from soapbar.core.fault import SoapFault
from soapbar.core.namespaces import NS
from soapbar.core.types import XsdType, xsd
from soapbar.core.wsdl import WsdlDefinition
from soapbar.core.wsdl.builder import build_wsdl, build_wsdl_bytes, build_wsdl_string
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file
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
    "SoapFault",
    "BindingStyle",
    "OperationSignature",
    "OperationParameter",
    "get_serializer",
    "SoapEnvelope",
    "SoapVersion",
    "build_request",
    "build_response",
    "build_fault",
    "http_headers",
    "WsdlDefinition",
    "parse_wsdl",
    "parse_wsdl_file",
    "build_wsdl",
    "build_wsdl_string",
    "build_wsdl_bytes",
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
