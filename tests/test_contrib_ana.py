"""Tests for soapbar.contrib.ana.AnaClient.

Offline tests drive a fake transport with canned ServiceANA DataSet replies
(no network). They lock the contract quirks that break silently against a
document/literal .asmx: the 12 HidroInventario filters in order, the lowercase
`origem`, and the PascalCase CotaOnline elements. A `live` test (deselected by
default) exercises the real endpoint.
"""
from __future__ import annotations

import pytest

from soapbar.client.transport import HttpTransport
from soapbar.contrib.ana import (
    ANA_NS,
    AnaClient,
    AnaError,
    OrigemTelemetrica,
    SerieHistoricaRegistro,
    TipoDados,
    _rows,
)

pytest.importorskip("httpx")


def _dataset_envelope(op: str, rows: list[dict[str, str]]) -> bytes:
    """A SOAP 1.1 response for *op* wrapping an ADO.NET DataSet (schema +
    diffgram). The rows deliberately inherit the MRCS default namespace, as the
    live service does, to exercise the local-name (`{*}Table`) matching."""
    body = ""
    for r in rows:
        cells = "".join(f"<{k}>{v}</{k}>" for k, v in r.items())
        body += f"<Table>{cells}</Table>"
    inner = (
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" id="NewDataSet"/>'
        '<diffgr:diffgram xmlns:diffgr="urn:schemas-microsoft-com:xml-diffgram-v1">'
        f"<NewDataSet>{body}</NewDataSet>"
        "</diffgr:diffgram>"
    )
    return (
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soap:Body>"
        f'<{op}Response xmlns="{ANA_NS}"><{op}Result>{inner}</{op}Result></{op}Response>'
        "</soap:Body></soap:Envelope>"
    ).encode()


class _FakeTransport(HttpTransport):
    def __init__(self, body: bytes) -> None:
        super().__init__()
        self._body = body
        self.sent: tuple[str, bytes, dict[str, str]] | None = None

    def send(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, bytes]:
        self.sent = (url, body, headers)
        return 200, "text/xml", self._body


def _client(op: str, rows: list[dict[str, str]]) -> tuple[AnaClient, _FakeTransport]:
    t = _FakeTransport(_dataset_envelope(op, rows))
    return AnaClient(transport=t), t


# -- _rows: diffgram flattening ------------------------------------------------

def test_rows_flattens_dataset_by_local_name() -> None:
    fragment = (
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>'
        '<diffgr:diffgram xmlns:diffgr="urn:schemas-microsoft-com:xml-diffgram-v1">'
        f'<NewDataSet xmlns="{ANA_NS}">'  # rows inherit MRCS → {*}Table match
        "<Table><EstacaoCodigo>61135000</EstacaoCodigo><Vazao>12.3</Vazao></Table>"
        "<Table><EstacaoCodigo>61136000</EstacaoCodigo><Vazao>4.5</Vazao></Table>"
        "</NewDataSet></diffgr:diffgram>"
    )
    rows = _rows(fragment)
    assert rows == [
        {"EstacaoCodigo": "61135000", "Vazao": "12.3"},
        {"EstacaoCodigo": "61136000", "Vazao": "4.5"},
    ]


# -- round-trip ---------------------------------------------------------------

def test_serie_historica_round_trip() -> None:
    ana, _t = _client("HidroSerieHistorica", [
        {"EstacaoCodigo": "61135000", "DataHora": "2026-01-01", "Vazao": "10"},
    ])
    serie = ana.serie_historica(
        cod_estacao="61135000", data_inicio="01/01/2026", data_fim="30/06/2026",
        tipo_dados=TipoDados.VAZOES, nivel_consistencia=1,
    )
    assert len(serie) == 1
    reg = serie[0]
    assert isinstance(reg, SerieHistoricaRegistro)
    assert reg.cod_estacao == "61135000"
    assert reg.data_hora == "2026-01-01"
    assert reg.raw["Vazao"] == "10"  # full row preserved verbatim


def test_catalogue_returns_raw_rows() -> None:
    ana, _t = _client("HidroEstado", [{"Codigo": "31", "Nome": "MINAS GERAIS"}])
    assert ana.hidro_estado() == [{"Codigo": "31", "Nome": "MINAS GERAIS"}]


# -- contract quirks (the silent-breakers) ------------------------------------

def _request_children(t: _FakeTransport, op: str) -> list[str]:
    """Ordered local names of the operation wrapper's child elements in the
    request (namespace/prefix-agnostic — the serializer qualifies them)."""
    from lxml import etree

    from soapbar.core.xml import local_name
    assert t.sent is not None
    root = etree.fromstring(t.sent[1])
    wrapper = next(e for e in root.iter() if local_name(e) == op)
    return [local_name(c) for c in wrapper]


def test_inventario_sends_12_filters_in_documented_order() -> None:
    ana, t = _client("HidroInventario", [])
    ana.inventario(
        cod_est_de="1", cod_est_ate="2", tp_est="3", nm_est="4", nm_rio="5",
        cod_sub_bacia="6", cod_bacia="7", nm_municipio="8", nm_estado="9",
        sg_resp="10", sg_oper="11", telemetrica="12",
    )
    names = _request_children(t, "HidroInventario")
    assert names == [
        "codEstDE", "codEstATE", "tpEst", "nmEst", "nmRio", "codSubBacia",
        "codBacia", "nmMunicipio", "nmEstado", "sgResp", "sgOper", "telemetrica",
    ]
    # No invented filters (the draft's earlier codRio/areaDE/statusEst mistakes).
    for bogus in ("codRio", "areaDE", "statusEst"):
        assert bogus not in names


def test_lista_estacoes_uses_lowercase_origem() -> None:
    ana, t = _client("ListaEstacoesTelemetricas", [])
    ana.estacoes_telemetricas(status="0", origem=OrigemTelemetrica.COTA_ONLINE)
    names = _request_children(t, "ListaEstacoesTelemetricas")
    assert "origem" in names       # lowercase, as on the wire
    assert "Origem" not in names   # NOT the documented PascalCase
    assert names == ["statusEstacoes", "origem"]


def test_cotaonline_uses_pascalcase_elements() -> None:
    ana, t = _client("IncluirDados_CotaOnline", [])
    ana.incluir_cota_online(
        login="u", senha="p", cod_estacao="61135000",
        data_hora="2026-01-01 00:00", cota="1.23",
    )
    names = _request_children(t, "IncluirDados_CotaOnline")
    for pascal in ("Login", "Senha", "CodEstacao", "DataHora"):
        assert pascal in names
    # camelCase variants (the read-op convention) must NOT appear.
    for camel in ("login", "senha", "codEstacao"):
        assert camel not in names


def test_soap_action_and_wrapper_namespace() -> None:
    ana, t = _client("HidroEstado", [])
    ana.hidro_estado("31")
    assert t.sent is not None
    _url, body_bytes, headers = t.sent
    action = headers.get("SOAPAction", "")
    assert "http://MRCS/HidroEstado" in action  # namespace + operation
    assert ANA_NS.encode() in body_bytes        # wrapper in the MRCS namespace


# -- error handling -----------------------------------------------------------

def test_empty_result_raises_anaerror() -> None:
    env = (
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soap:Body>"
        f'<HidroRioResponse xmlns="{ANA_NS}"><HidroRioResult></HidroRioResult>'
        "</HidroRioResponse></soap:Body></soap:Envelope>"
    ).encode()
    ana = AnaClient(transport=_FakeTransport(env))
    with pytest.raises(AnaError, match="empty result"):
        ana.hidro_rio("999")


def test_context_manager_closes() -> None:
    with _client("HidroEstado", [])[0] as ana:
        assert ana.hidro_estado() == []


# -- live (deselected by default; hits the real ANA endpoint) -----------------

@pytest.mark.live
def test_live_lista_estacoes_telemetricas() -> None:
    """Smoke-test the real ServiceANA endpoint. Run with ``pytest -m live``.

    Validates that the protocol still round-trips end-to-end; the exact DataSet
    column names per operation should be confirmed here against production.
    """
    with AnaClient() as ana:
        rows = ana.estacoes_telemetricas(status="0")
    assert isinstance(rows, list)
    assert rows, "expected at least one telemetric station"
