# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Core SOAP toolkit re-exports."""
from __future__ import annotations

from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import (
    SoapEnvelope,
    SoapVersion,
    build_fault,
    build_request,
    build_response,
    build_wsa_response_headers,
)
from soapbar.core.fault import SoapFault
from soapbar.core.namespaces import NS
from soapbar.core.types import XsdType, xsd
from soapbar.core.wsdl import WsdlDefinition
from soapbar.core.wsdl.builder import build_wsdl
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file
from soapbar.core.xml import parse_xml, parse_xml_document

__all__ = [
    "NS",
    "BindingStyle",
    "OperationParameter",
    "OperationSignature",
    "SoapEnvelope",
    "SoapFault",
    "SoapVersion",
    "WsdlDefinition",
    "XsdType",
    "build_fault",
    "build_request",
    "build_response",
    "build_wsa_response_headers",
    "build_wsdl",
    "parse_wsdl",
    "parse_wsdl_file",
    "parse_xml",
    "parse_xml_document",
    "xsd",
]
