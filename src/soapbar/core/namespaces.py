"""SOAP/XML namespace URI constants and helpers."""
from __future__ import annotations

from typing import ClassVar


class _Namespaces:
    # Namespace URI constants
    SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/"
    SOAP_ENC = "http://schemas.xmlsoap.org/soap/encoding/"
    SOAP12_ENV = "http://www.w3.org/2003/05/soap-envelope"
    SOAP12_ENC = "http://www.w3.org/2003/05/soap-encoding"
    XSD = "http://www.w3.org/2001/XMLSchema"
    XSI = "http://www.w3.org/2001/XMLSchema-instance"
    WSDL = "http://schemas.xmlsoap.org/wsdl/"
    WSDL_SOAP = "http://schemas.xmlsoap.org/wsdl/soap/"
    WSDL_SOAP12 = "http://schemas.xmlsoap.org/wsdl/soap12/"
    WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    WSA = "http://www.w3.org/2005/08/addressing"
    SOAP_RPC = "http://www.w3.org/2003/05/soap-rpc"

    DEFAULT_PREFIXES: ClassVar[dict[str, str]] = {
        SOAP_ENV: "soapenv",
        SOAP_ENC: "soapenc",
        SOAP12_ENV: "soap12",
        SOAP12_ENC: "soap12enc",
        XSD: "xsd",
        XSI: "xsi",
        WSDL: "wsdl",
        WSDL_SOAP: "soap",
        WSDL_SOAP12: "wsoap12",
        WSSE: "wsse",
        WSU: "wsu",
        WSA: "wsa",
        SOAP_RPC: "rpc",
    }

    REVERSE_PREFIXES: ClassVar[dict[str, str]] = {v: k for k, v in DEFAULT_PREFIXES.items()}

    def prefix_for(self, ns: str) -> str | None:
        return self.DEFAULT_PREFIXES.get(ns)

    def qname(self, ns: str, local: str) -> str:
        """Return Clark notation {ns}local."""
        return f"{{{ns}}}{local}"

    def split_qname(self, clark: str) -> tuple[str | None, str]:
        """Split Clark notation {ns}local → (ns, local). Bare names return (None, name)."""
        if clark.startswith("{"):
            close = clark.index("}")
            return clark[1:close], clark[close + 1:]
        return None, clark


NS = _Namespaces()
