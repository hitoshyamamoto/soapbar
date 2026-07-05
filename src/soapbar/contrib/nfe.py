# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Typed client for SEFAZ NF-e (Brazilian electronic invoice), layout 4.00.

NF-e web services are SOAP 1.2, document/literal *bare*: the body is a single
``nfeDadosMsg`` element carrying the raw NF-e message XML. Authentication is
mutual TLS with an ICP-Brasil certificate, and the ``<infNFe>`` element must be
signed by its ``Id`` with a specific algorithm set. This client wires those
pieces together:

    from soapbar.contrib.nfe import NfeClient

    nfe = NfeClient(pfx_path="cert.pfx", pfx_password="…")
    status = nfe.status_servico(
        "https://nfe.sefaz.uf/ws/NFeStatusServico4", uf="31", tp_amb=2,
    )
    if status.operational:          # cStat == 107
        print(status.x_motivo)

    signed = nfe.sign(nfe_xml)      # enveloped XML-DSig over <infNFe>

Scope: this owns the *protocol* (mTLS transport, the bare ``nfeDadosMsg``
envelope, `<infNFe>` signing, and `cStat`/`xMotivo` parsing) — not the full
layout-4 data model. It implements the status and protocol-consult queries and
the signing step; building/validating full NF-e documents (autorização,
lotes, eventos) against the official XSDs is left to the caller.

Endpoints differ per UF authorizer; pass the right URL for the service.
Requires ``soapbar[nfe]`` (httpx, signxml, cryptography).
"""
from __future__ import annotations

from dataclasses import dataclass

from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport, load_pkcs12
from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import SoapVersion
from soapbar.core.exceptions import SoapbarError
from soapbar.core.types import AnyXmlType
from soapbar.core.wssecurity import sign_element_by_id

#: NF-e message content namespace (the <consStatServ>, <NFe>, … elements).
NFE_NS = "http://www.portalfiscal.inf.br/nfe"
#: Per-service WSDL namespaces (standardised nationally for layout 4.00).
STATUS_SERVICO_NS = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeStatusServico4"
CONSULTA_PROTOCOLO_NS = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4"

# SEFAZ-mandated signing parameters for <infNFe>.
_SIGN = {"signature_method": "rsa-sha1", "digest_method": "sha1", "c14n": "inclusive"}


class NfeError(SoapbarError):
    """Base class for NF-e client errors."""


class NfeInputError(NfeError):
    """A caller-side precondition failed: a malformed argument (``cUF``,
    ``tpAmb``, ``chNFe``), a document with no signable ``<infNFe Id=...>``, or a
    missing certificate. Distinct from a fault the SEFAZ web service returns,
    which surfaces as a :class:`~soapbar.core.fault.SoapFault`."""


def _local(elem_qname: str) -> str:
    return elem_qname.rsplit("}", 1)[-1]


def _check_tp_amb(tp_amb: int) -> None:
    # tpAmb is interpolated into the message body; only 1 (produção) / 2
    # (homologação) are valid, so reject anything else rather than emit it.
    if tp_amb not in (1, 2):
        raise NfeInputError(f"tpAmb must be 1 (produção) or 2 (homologação), got {tp_amb!r}")


def build_cons_stat_serv(uf: str, tp_amb: int = 2) -> str:
    """Build a ``consStatServ`` (service-status query) message."""
    # cUF is a 2-digit IBGE state code; validate before interpolating it into
    # the body (an unchecked value is an XML-injection vector).
    if not (len(uf) == 2 and uf.isdigit()):
        raise NfeInputError(f"cUF (uf) must be a 2-digit IBGE code, got {uf!r}")
    _check_tp_amb(tp_amb)
    return (
        f'<consStatServ xmlns="{NFE_NS}" versao="4.00">'
        f"<tpAmb>{tp_amb}</tpAmb><cUF>{uf}</cUF><xServ>STATUS</xServ>"
        f"</consStatServ>"
    )


def build_cons_sit_nfe(chave: str, tp_amb: int = 2) -> str:
    """Build a ``consSitNFe`` (protocol/consult) message for a 44-digit key."""
    _check_tp_amb(tp_amb)
    return (
        f'<consSitNFe xmlns="{NFE_NS}" versao="4.00">'
        f"<tpAmb>{tp_amb}</tpAmb><xServ>CONSULTAR</xServ><chNFe>{chave}</chNFe>"
        f"</consSitNFe>"
    )


def extract_infnfe_id(nfe_xml: bytes | str) -> str:
    """Return the ``Id`` of the ``<infNFe>`` element (``NFe`` + 44-char key)."""
    from lxml import etree

    data = nfe_xml.encode() if isinstance(nfe_xml, str) else nfe_xml
    root = etree.fromstring(data)
    inf = root.find(f".//{{{NFE_NS}}}infNFe")
    if inf is None or not inf.get("Id"):
        raise NfeInputError("document has no <infNFe Id=...> element to sign")
    return str(inf.get("Id"))


def sign_nfe(nfe_xml: bytes | str, cert_pem: bytes, key_pem: bytes) -> bytes:
    """Sign the ``<infNFe>`` element with the SEFAZ-mandated algorithm set."""
    data = nfe_xml.encode() if isinstance(nfe_xml, str) else nfe_xml
    return sign_element_by_id(
        data,
        extract_infnfe_id(data),
        key_pem,
        cert_pem,
        end_cert_only=True,
        **_SIGN,
    )


@dataclass(frozen=True)
class NfeStatusResult:
    """Parsed ``ret*`` reply.

    ``c_stat``/``x_motivo`` are the reply's top-level status (for
    ``retConsSitNFe`` that is the *query* status). When the reply carries a
    nested authorization protocol (``protNFe/infProt``, as ``consultar_protocolo``
    returns), ``prot_c_stat``/``prot_x_motivo``/``n_prot`` expose it directly so
    callers needn't parse ``.raw``.
    """

    c_stat: int | None
    x_motivo: str | None
    tp_amb: str | None = None
    prot_c_stat: int | None = None
    prot_x_motivo: str | None = None
    n_prot: str | None = None
    raw: str = ""

    @property
    def operational(self) -> bool:
        """True when ``cStat == 107`` ("Serviço em Operação")."""
        return self.c_stat == 107

    @property
    def authorized(self) -> bool:
        """True when the nested protocol status is ``100`` ("Autorizado o uso")."""
        return self.prot_c_stat == 100

    @staticmethod
    def _as_int(value: str | None) -> int | None:
        return int(value) if value and value.lstrip("-").isdigit() else None

    @classmethod
    def from_xml(cls, xml: str) -> NfeStatusResult:
        from lxml import etree

        root = etree.fromstring(xml.encode())
        values: dict[str, str] = {}
        for child in root.iter():
            if isinstance(child.tag, str):
                values.setdefault(_local(child.tag), (child.text or "").strip())

        # Nested authorization protocol, if present (protNFe/infProt).
        prot: dict[str, str] = {}
        inf_prot = next(
            (e for e in root.iter() if isinstance(e.tag, str) and _local(e.tag) == "infProt"),
            None,
        )
        if inf_prot is not None:
            for c in inf_prot.iter():
                if isinstance(c.tag, str):
                    prot.setdefault(_local(c.tag), (c.text or "").strip())

        return cls(
            c_stat=cls._as_int(values.get("cStat")),
            x_motivo=values.get("xMotivo"),
            tp_amb=values.get("tpAmb"),
            prot_c_stat=cls._as_int(prot.get("cStat")),
            prot_x_motivo=prot.get("xMotivo"),
            n_prot=prot.get("nProt"),
            raw=xml,
        )


class NfeClient:
    """Mutual-TLS NF-e client for the layout-4.00 web services."""

    def __init__(
        self,
        *,
        pfx_path: str | None = None,
        pfx_password: str | None = None,
        cert_pem: bytes | None = None,
        key_pem: bytes | None = None,
        verify_ssl: bool = True,
        ca_bundle: str | None = None,
        transport: HttpTransport | None = None,
    ) -> None:
        """Build the client.

        ``ca_bundle`` is the path to a CA bundle for server verification — set
        it to the ICP-Brasil chain when SEFAZ roots are not in the default
        trust store (otherwise TLS verification may fail). Provide the
        certificate as ``pfx_path``/``pfx_password`` or ``cert_pem``/``key_pem``,
        or inject a fully-built ``transport``.
        """
        if pfx_path is not None:
            cert_pem, key_pem = load_pkcs12(pfx_path, pfx_password)
        self._cert_pem = cert_pem
        self._key_pem = key_pem
        if transport is not None:
            self._transport = transport
        elif cert_pem is not None and key_pem is not None:
            self._transport = HttpTransport(
                client_cert=(cert_pem, key_pem), verify_ssl=verify_ssl, ca_bundle=ca_bundle
            )
        else:
            self._transport = HttpTransport(verify_ssl=verify_ssl, ca_bundle=ca_bundle)

    def _send(self, endpoint: str, service_ns: str, operation: str, message: str) -> str:
        client = SoapClient.manual(
            address=endpoint,
            binding_style=BindingStyle.DOCUMENT_LITERAL,
            soap_version=SoapVersion.SOAP_12,
            transport=self._transport,
        )
        client.register_operation(
            OperationSignature(
                name=operation,
                input_params=[
                    OperationParameter("nfeDadosMsg", AnyXmlType(), namespace=service_ns)
                ],
                # SEFAZ returns the result inside <nfeResultMsg> (NOT
                # <nfeDadosMsg>, which is request-only) — getting this wrong
                # makes every call return nothing.
                output_params=[
                    OperationParameter("nfeResultMsg", AnyXmlType(), namespace=service_ns,
                                       required=False)
                ],
                soap_action=f"{service_ns}/{operation}",
                input_namespace=service_ns,
                output_namespace=service_ns,
            )
        )
        result = client.call(operation, nfeDadosMsg=message)
        return result if isinstance(result, str) else str(result or "")

    def status_servico(self, endpoint: str, *, uf: str, tp_amb: int = 2) -> NfeStatusResult:
        """Call ``NFeStatusServico4`` — the health check (``cStat == 107`` is OK)."""
        body = build_cons_stat_serv(uf, tp_amb)
        return NfeStatusResult.from_xml(
            self._send(endpoint, STATUS_SERVICO_NS, "nfeStatusServicoNF", body)
        )

    def consultar_protocolo(self, endpoint: str, chave: str, *, tp_amb: int = 2) -> NfeStatusResult:
        """Call ``NFeConsultaProtocolo4`` for a 44-digit access key.

        ``.c_stat`` here is the *query envelope* status of the ``retConsSitNFe``
        reply (e.g. ``138`` "Documento localizado"). The document's authorization
        status is exposed separately as ``.prot_c_stat`` / ``.prot_x_motivo`` /
        ``.n_prot`` (e.g. ``100`` "Autorizado"), with ``.authorized`` as a
        shortcut — no need to parse ``.raw``.
        """
        if len(chave) != 44 or not chave.isdigit():
            raise NfeInputError(f"chNFe must be 44 digits, got {chave!r}")
        body = build_cons_sit_nfe(chave, tp_amb)
        return NfeStatusResult.from_xml(
            self._send(endpoint, CONSULTA_PROTOCOLO_NS, "nfeConsultaNF", body)
        )

    def sign(self, nfe_xml: bytes | str) -> bytes:
        """Sign an NF-e document's ``<infNFe>`` with the configured certificate."""
        if self._cert_pem is None or self._key_pem is None:
            raise NfeInputError("a certificate (pfx_path or cert_pem/key_pem) is required to sign")
        return sign_nfe(nfe_xml, self._cert_pem, self._key_pem)

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> NfeClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
