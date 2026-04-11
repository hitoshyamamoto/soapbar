"""SOAP server components."""
from __future__ import annotations

from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp
from soapbar.server.service import SoapService, soap_operation
from soapbar.server.wsgi import WsgiSoapApp

__all__ = [
    "AsgiSoapApp",
    "SoapApplication",
    "SoapService",
    "WsgiSoapApp",
    "soap_operation",
]
