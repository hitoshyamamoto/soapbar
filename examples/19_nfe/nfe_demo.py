"""
examples/19_nfe/nfe_demo.py — Consume a SEFAZ NF-e web service with soapbar.

READY CLIENT
    For real use, prefer the typed `soapbar.contrib.nfe.NfeClient`
    (`soapbar[nfe]`) — it wraps mutual TLS, the bare `nfeDadosMsg` envelope,
    `<infNFe>` signing, and `cStat` parsing. This script shows the raw core
    APIs that client is built on.

PREREQUISITES (external — cannot be bypassed in code)
    Running this against a live SEFAZ endpoint needs an ICP-Brasil A1 test
    certificate (a `.pfx`) and network access to a homologação authorizer. The
    two soapbar core capabilities it relies on:
      * mutual TLS — HttpTransport(client_cert=...) + load_pkcs12
      * Id-targeted signing — sign_element_by_id
    `main()` does not hit the network; it prints guidance. Provide a real
    certificate + endpoint and call `status_servico()` to exercise it.

WHAT THIS DEMONSTRATES
    The hardest real-world conformance case: a SOAP 1.2 government service that
    requires mutual TLS with a national PKI certificate AND an XML Digital
    Signature applied to an internal element selected by Id.

SERVICE FACTS (verified against the SEFAZ "Manual de Orientacao do Contribuinte"
and "Manual de Integracao do Contribuinte", and the Portal Nacional da NF-e)
    Transport      : SOAP 1.2; Style/Encoding Document/Literal.
    THE signature rule:
        The signature is applied to the <infNFe> element, identified by its `Id`
        attribute (the 44-char access key prefixed with the literal "NFe"), and
        referenced by <Reference URI="#NFe...">. It is NOT applied to the SOAP
        envelope or the whole document.
    Mandated algorithms:
        Canonicalization : http://www.w3.org/TR/2001/REC-xml-c14n-20010315
        SignatureMethod  : http://www.w3.org/2000/09/xmldsig#rsa-sha1
        DigestMethod     : http://www.w3.org/2000/09/xmldsig#sha1
        Transforms       : enveloped-signature + C14N
        KeyInfo          : X509Data/X509Certificate, end-entity cert only (EndCertOnly)
        Certificate      : ICP-Brasil A1 or A3, EKU = Client Authentication
    Services (layout "4"):
        NFeAutorizacao4, NFeRetAutorizacao4, NFeConsultaProtocolo4,
        NFeStatusServico4, NFeInutilizacao4, RecepcaoEvento4
        (WSDLs differ per authorizer: SVRS, SVAN, SP, etc.)
    Environments   : tpAmb=2 homologacao (test), tpAmb=1 producao.
    Health check   : NFeStatusServico4 returning cStat=107 means "service in operation".

REQUIREMENTS
    soapbar[security] (signxml + cryptography), an ICP-Brasil test certificate,
    and network access to a SEFAZ homologacao endpoint.

Run:
    uv run python examples/19_nfe/nfe_demo.py
"""

from __future__ import annotations

from soapbar import HttpTransport, SoapClient, SoapFault, load_pkcs12
from soapbar.core.wssecurity import sign_element_by_id

# --- configuration (edit these) --------------------------------------------
# Use a HOMOLOGACAO (test) endpoint and a TEST certificate. Never commit real certs.
PFX_PATH = "/path/to/icp-brasil-a1-test.pfx"  # PKCS#12 (A1)
PFX_PASSWORD = "changeit"  # noqa: S105 - placeholder, not a real secret
STATUS_WSDL = "https://homologacao.example-sefaz/ws/NFeStatusServico4.asmx?wsdl"  # replace per UF
NFE_NS = "http://www.portalfiscal.inf.br/nfe"
C_UF = "31"  # IBGE code for the UF (example: 31 = MG)
TP_AMB = "2"  # 2 = homologacao


def build_transport() -> HttpTransport:
    """Build an mTLS transport from a PKCS#12 (.pfx) ICP-Brasil A1 certificate.

    Uses load_pkcs12: converts the .pfx to in-memory PEM (the key
    never touches the disk), which HttpTransport presents on the handshake.
    """
    cert_pem, key_pem = load_pkcs12(PFX_PATH, PFX_PASSWORD)
    return HttpTransport(client_cert=(cert_pem, key_pem))


def extract_infnfe_id(nfe_xml: bytes | str) -> str:
    """Return the `Id` of the <infNFe> element ("NFe" + 44-char access key)."""
    from lxml import etree

    data = nfe_xml.encode() if isinstance(nfe_xml, str) else nfe_xml
    root = etree.fromstring(data)
    inf = root.find(f".//{{{NFE_NS}}}infNFe")
    if inf is None or not inf.get("Id"):
        raise ValueError("document has no <infNFe Id=...> element to sign")
    return str(inf.get("Id"))


def sign_infnfe(nfe_xml: bytes | str, cert_pem: bytes, key_pem: bytes) -> bytes:
    """Sign the <infNFe> element by its Id, per the SEFAZ-mandated algorithm set.

    Uses sign_element_by_id: an enveloped signature whose single Reference targets
    #<infNFe Id>, with RSA-SHA1 / SHA-1 / inclusive C14N and an end-entity-only
    KeyInfo — exactly what SEFAZ requires.
    """
    data = nfe_xml.encode() if isinstance(nfe_xml, str) else nfe_xml
    return sign_element_by_id(
        data,
        extract_infnfe_id(data),
        key_pem,  # private key (PEM bytes accepted by signxml)
        cert_pem,  # end-entity certificate (PEM bytes)
        signature_method="rsa-sha1",
        digest_method="sha1",
        c14n="inclusive",  # http://www.w3.org/TR/2001/REC-xml-c14n-20010315
        end_cert_only=True,
    )


def status_servico() -> None:
    """Call NFeStatusServico4 and report cStat (107 == service in operation)."""
    transport = build_transport()
    client = SoapClient(wsdl_url=STATUS_WSDL, transport=transport)

    # The status request body (consStatServ) is small and unsigned; only the NFe
    # itself requires the infNFe signature. Build per the service schema/version.
    cons_stat_serv = (
        f'<consStatServ xmlns="{NFE_NS}" versao="4.00">'
        f"<tpAmb>{TP_AMB}</tpAmb><cUF>{C_UF}</cUF><xServ>STATUS</xServ>"
        f"</consStatServ>"
    )

    try:
        # Operation name varies by WSDL; confirm against the service's WSDL.
        resp = client.call("nfeStatusServicoNF", nfeDadosMsg=cons_stat_serv)
    except SoapFault as fault:
        print(f"SOAP fault: {fault.faultcode} / {fault.faultstring}")
        return

    # Parse cStat / xMotivo out of the returned retConsStatServ.
    print("Raw response (parse cStat/xMotivo):", str(resp)[:400])


def main() -> None:
    print("SEFAZ NF-e reference example.")
    print(
        "Configure PFX_PATH (an ICP-Brasil A1 test cert) and STATUS_WSDL for a "
        "homologação authorizer, then call status_servico() to exercise it. "
        "soapbar's mTLS (load_pkcs12 + HttpTransport) and <infNFe> Id-signing "
        "(sign_element_by_id) are ready; the remaining prerequisites are the "
        "certificate and endpoint."
    )
    # status_servico()  # enable once a real cert + endpoint are configured


if __name__ == "__main__":
    main()
