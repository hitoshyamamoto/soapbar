"""Tests for soapbar.contrib.nfe.NfeClient.

Offline tests drive a fake transport with canned SEFAZ replies (no network, no
certificate). Signing is exercised against an in-test certificate. A `live`
test (gated on NFE_* env vars + a homologação cert) is provided for real runs.
"""
from __future__ import annotations

import datetime

import pytest

from soapbar.client.transport import HttpTransport
from soapbar.contrib.nfe import (
    CONSULTA_PROTOCOLO_NS,
    NFE_NS,
    STATUS_SERVICO_NS,
    NfeClient,
    NfeError,
    NfeStatusResult,
    build_cons_stat_serv,
    extract_infnfe_id,
    sign_nfe,
)

pytest.importorskip("httpx")
crypto = pytest.importorskip("cryptography")
pytest.importorskip("signxml")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from lxml import etree  # noqa: E402

DS = "http://www.w3.org/2000/09/xmldsig#"


def _result_envelope(inner: str, wrapper_ns: str = STATUS_SERVICO_NS) -> bytes:
    # SEFAZ returns the result inside <nfeResultMsg> (calibrated to the real
    # service, not to the implementation — registering <nfeDadosMsg> for the
    # response makes every call return nothing).
    return (
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body>'
        f'<nfeResultMsg xmlns="{wrapper_ns}">{inner}</nfeResultMsg>'
        "</soap:Body></soap:Envelope>"
    ).encode()


def _ret(c_stat: str, x_motivo: str) -> bytes:
    inner = (
        f'<retConsStatServ xmlns="{NFE_NS}" versao="4.00">'
        f"<tpAmb>2</tpAmb><cStat>{c_stat}</cStat><xMotivo>{x_motivo}</xMotivo>"
        "</retConsStatServ>"
    )
    return _result_envelope(inner)


class _FakeTransport(HttpTransport):
    def __init__(self, body: bytes) -> None:
        super().__init__()
        self._body = body
        self.sent: tuple[str, bytes, dict[str, str]] | None = None

    def send(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, bytes]:
        self.sent = (url, body, headers)
        return 200, "application/soap+xml", self._body


@pytest.fixture(scope="module")
def keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nfe-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


_NFE_DOC = (
    f'<NFe xmlns="{NFE_NS}"><infNFe Id="NFe31999" versao="4.00">'
    "<ide><cUF>31</cUF></ide></infNFe></NFe>"
)


# --- message builders / parsing ----------------------------------------------
def test_build_cons_stat_serv() -> None:
    msg = build_cons_stat_serv("31", 2)
    assert f'xmlns="{NFE_NS}"' in msg
    assert "<cUF>31</cUF>" in msg and "<xServ>STATUS</xServ>" in msg


def test_status_result_parsing_and_operational() -> None:
    result = NfeStatusResult.from_xml(
        f'<retConsStatServ xmlns="{NFE_NS}"><cStat>107</cStat>'
        "<xMotivo>Servico em Operacao</xMotivo><tpAmb>2</tpAmb></retConsStatServ>"
    )
    assert result.c_stat == 107
    assert result.operational is True
    assert result.x_motivo == "Servico em Operacao"
    assert NfeStatusResult.from_xml(
        f'<x xmlns="{NFE_NS}"><cStat>108</cStat><xMotivo>Paralisado</xMotivo></x>'
    ).operational is False


# --- transport: bare body + cStat parsing ------------------------------------
def test_status_servico_sends_bare_body_and_parses_cstat() -> None:
    transport = _FakeTransport(_ret("107", "Servico em Operacao"))
    with NfeClient(transport=transport) as nfe:
        result = nfe.status_servico("https://uf/ws/NFeStatusServico4", uf="31", tp_amb=2)
    # The cStat is extracted from a real <nfeResultMsg> response (regression: a
    # <nfeDadosMsg> output mapping returned nothing → "Document is empty").
    assert result.operational
    assert result.c_stat == 107
    # The request body is bare: <nfeDadosMsg> carrying <consStatServ>, SOAP 1.2.
    assert transport.sent is not None
    body = transport.sent[1].decode()
    assert "www.w3.org/2003/05/soap-envelope" in body  # SOAP 1.2
    assert "nfeDadosMsg" in body and "<consStatServ" in body
    assert "<cUF>31</cUF>" in body
    assert "nfeStatusServicoNF" not in body  # no operation-named wrapper
    assert "nfeResultMsg" not in body  # response-only element, never in the request


def test_consultar_protocolo_returns_query_status() -> None:
    # retConsSitNFe carries the *query* cStat at the top and the document's
    # authorization status nested in protNFe/infProt (N2). .c_stat is the former.
    inner = (
        f'<retConsSitNFe xmlns="{NFE_NS}" versao="4.00"><tpAmb>2</tpAmb>'
        "<cStat>138</cStat><xMotivo>Documento localizado</xMotivo>"
        "<protNFe><infProt><cStat>100</cStat><xMotivo>Autorizado</xMotivo>"
        "<nProt>131250000000001</nProt></infProt></protNFe></retConsSitNFe>"
    )
    transport = _FakeTransport(_result_envelope(inner, wrapper_ns=CONSULTA_PROTOCOLO_NS))
    with NfeClient(transport=transport) as nfe:
        result = nfe.consultar_protocolo("https://uf/ws", "3" * 44)
    assert result.c_stat == 138  # query-envelope status, not the nested 100
    # The nested authorization protocol is exposed directly (no .raw parsing).
    assert result.prot_c_stat == 100
    assert result.prot_x_motivo == "Autorizado"
    assert result.n_prot == "131250000000001"
    assert result.authorized is True
    body = transport.sent[1].decode()
    assert "<consSitNFe" in body and "<chNFe>" in body


def test_status_result_has_no_protocol_fields_when_flat() -> None:
    # A flat retConsStatServ has no protNFe/infProt → protocol fields stay None.
    result = NfeStatusResult.from_xml(
        f'<retConsStatServ xmlns="{NFE_NS}"><cStat>107</cStat></retConsStatServ>'
    )
    assert result.prot_c_stat is None and result.n_prot is None
    assert result.authorized is False


def test_ca_bundle_is_passed_to_transport(keypair) -> None:
    cert_pem, key_pem = keypair
    nfe = NfeClient(cert_pem=cert_pem, key_pem=key_pem, ca_bundle="/etc/icp-brasil.pem")
    assert nfe._transport.ca_bundle == "/etc/icp-brasil.pem"
    assert nfe._transport.client_cert == (cert_pem, key_pem)


def test_consultar_protocolo_validates_key() -> None:
    with (
        NfeClient(transport=_FakeTransport(_ret("100", "ok"))) as nfe,
        pytest.raises(NfeError),
    ):
        nfe.consultar_protocolo("https://uf/ws", "123")  # not 44 digits


# --- signing -----------------------------------------------------------------
def test_extract_infnfe_id() -> None:
    assert extract_infnfe_id(_NFE_DOC) == "NFe31999"
    with pytest.raises(NfeError):
        extract_infnfe_id(f'<NFe xmlns="{NFE_NS}"><infNFe/></NFe>')


def test_sign_uses_sefaz_algorithm_set_and_placement(keypair) -> None:
    cert_pem, key_pem = keypair
    signed = sign_nfe(_NFE_DOC, cert_pem, key_pem)
    root = etree.fromstring(signed)
    sig = root.find(f".//{{{DS}}}Signature")
    assert sig is not None
    # Sibling of <infNFe>, inside <NFe>.
    assert etree.QName(sig.getparent()).localname == "NFe"
    si = sig.find(f"{{{DS}}}SignedInfo")
    assert si.find(f"{{{DS}}}SignatureMethod").get("Algorithm").endswith("rsa-sha1")
    assert si.find(f"{{{DS}}}CanonicalizationMethod").get("Algorithm") == (
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )
    assert si.find(f"{{{DS}}}Reference").get("URI") == "#NFe31999"
    # End-entity cert only, no RSA KeyValue.
    ki = sig.find(f"{{{DS}}}KeyInfo")
    assert len(ki.findall(f".//{{{DS}}}X509Certificate")) == 1
    assert ki.find(f".//{{{DS}}}KeyValue") is None


def test_client_sign_via_pem(keypair) -> None:
    cert_pem, key_pem = keypair
    with NfeClient(cert_pem=cert_pem, key_pem=key_pem) as nfe:
        signed = nfe.sign(_NFE_DOC)
    assert b"Signature" in signed


def test_sign_requires_certificate() -> None:
    with (
        NfeClient(transport=_FakeTransport(b"")) as nfe,
        pytest.raises(NfeError, match="certificate"),
    ):
        nfe.sign(_NFE_DOC)


@pytest.mark.live
def test_live_status_servico() -> None:
    # Real SEFAZ **homologação** call. Run with: pytest -m live
    # Needs NFE_PFX, NFE_PFX_PASSWORD, NFE_STATUS_URL, NFE_UF env vars.
    #
    # Safety: this test is hard-pinned to homologação (tpAmb=2) and refuses a
    # production-looking endpoint, so a real certificate can never drive a
    # produção transaction by accident. The PFX password is read inline and
    # never bound to a named local, so it cannot surface in a traceback.
    import os

    pfx = os.environ.get("NFE_PFX")
    url = os.environ.get("NFE_STATUS_URL")
    if not pfx or not url:
        pytest.skip("set NFE_PFX / NFE_PFX_PASSWORD / NFE_STATUS_URL / NFE_UF to run")
    if "producao" in url.lower() or "homologacao" not in url.lower():
        pytest.skip(f"refusing a non-homologação endpoint: {url}")
    with NfeClient(pfx_path=pfx, pfx_password=os.environ.get("NFE_PFX_PASSWORD")) as nfe:
        result = nfe.status_servico(url, uf=os.environ["NFE_UF"], tp_amb=2)
    assert result.c_stat is not None
