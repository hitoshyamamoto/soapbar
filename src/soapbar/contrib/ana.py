# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Typed client for ANA ServiceANA (Brazilian National Water Agency telemetry).

The legacy ANA hydrometeorological web service (``telemetriaws1.ana.gov.br``)
is a classic ASP.NET ``.asmx`` endpoint: SOAP 1.1/1.2, document/literal
*wrapped*, namespace ``http://MRCS/``, quoted ``SOAPAction``. Responses carry
an ADO.NET DataSet — an inline ``xsd:schema`` followed by a Microsoft
``diffgram`` — inside the ``<OperacaoResult>`` element, which this client
receives via :class:`~soapbar.core.types.AnyXmlType` and flattens into plain
dict rows.

All 12 operations exposed by the service are covered (protocol verified against
the live endpoint, July 2026):

======================================  =============================================
Operation                               Purpose
======================================  =============================================
``DadosHidrometeorologicos``            Telemetric data per station (validated)
``DadosHidrometeorologicosGerais``      Telemetric data, raw/unvalidated filters
``HidroBaciaSubBacia``                  Basins and sub-basins catalogue
``HidroEntidades``                      Entities (owners/operators) catalogue
``HidroEstado``                         States (UF) catalogue
``HidroMunicipio``                      Municipalities catalogue
``HidroRio``                            Rivers catalogue
``HidroInventario``                     Full station inventory (12 filters)
``HidroSerieHistorica``                 Historical series (cotas/chuvas/vazões)
``ListaEstacoesTelemetricas``           Registered telemetric stations
``IncluirDados_CotaOnline``             CotaOnline data insert (restricted, auth)
``Excluir_CotaOnline``                  CotaOnline data delete (restricted, auth)
======================================  =============================================

Contract quirks worth knowing (all observed on live envelopes):

* ``ListaEstacoesTelemetricas`` documents the second parameter as *Origem*
  but the actual element on the wire is lowercase ``origem``.
* The CotaOnline write operations use *PascalCase* elements (``Login``,
  ``Senha``, ``CodEstacao``, ``DataHora``…) unlike every read operation, and
  authenticate with plaintext credentials in the body — they are restricted
  to registered CotaOnline partners (``telemetria@ana.gov.br``).
* Because this is document/literal, the receiver validates the request body
  against the schema ``sequence``: a wrong element *case* or *order* is
  rejected silently, so ``input_params`` are kept in the documented order.
* Result fragments have two roots (``xs:schema`` + ``diffgr:diffgram``) and
  the DataSet rows inherit the MRCS default namespace; the row element is named
  per operation and is sometimes even misspelled — ``Table`` for the catalogues,
  ``SerieHistorica`` for the series, and (typo and all) ``DadosHidrometereologicos``
  for the telemetric reads — so :func:`_rows` reads the diffgram's DataSet
  children generically rather than by a fixed table name.
* ``DadosHidrometeorologicos`` / ``…Gerais`` report "no data for this
  station/period" (or a rejected filter) not as an empty DataSet or a fault but
  as a single row with an ``<Error>`` column; this client raises
  :class:`AnaServiceError` carrying that message.

The row *column names* inside the DataSet vary per operation and are returned
verbatim in each row dict (and in ``SerieHistoricaRegistro.raw``); the two
typed shortcut fields are best-effort and fall back to ``None``.

Example::

    from soapbar.contrib.ana import AnaClient, TipoDados

    with AnaClient() as ana:
        estacoes = ana.estacoes_telemetricas(status="0")
        serie = ana.serie_historica(
            cod_estacao="61135000",
            data_inicio="01/01/2026", data_fim="30/06/2026",
            tipo_dados=TipoDados.VAZOES, nivel_consistencia=1,
        )

.. warning::
   ANA announced this service's discontinuation (superseded by the REST
   ``Hidro_Webservice``); it remains online well past the announced date but
   should be treated as **legacy**. Consider this contrib a bridge for systems
   already built around the SOAP contract.

Requires ``soapbar[client]`` (httpx). Installable via ``soapbar[ana]``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport
from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.envelope import SoapVersion
from soapbar.core.exceptions import SoapbarError
from soapbar.core.types import AnyXmlType, xsd
from soapbar.core.xml import local_name, parse_xml

#: ServiceANA namespace (yes, it is literally ``http://MRCS/``).
ANA_NS = "http://MRCS/"
DEFAULT_ENDPOINT = "https://telemetriaws1.ana.gov.br/ServiceANA.asmx"


class AnaError(SoapbarError):
    """Base class for ANA client errors."""


class AnaServiceError(AnaError):
    """The ServiceANA endpoint returned no usable data: an empty result, or a
    single-``<Error>``-column DataSet carrying the service's own "no data for
    this station/period" (or rejected-filter) message. Distinct from a SOAP
    fault, which surfaces as a :class:`~soapbar.core.fault.SoapFault`."""


class TipoDados(IntEnum):
    """``tipoDados`` values for ``HidroSerieHistorica``."""
    COTAS = 1
    CHUVAS = 2
    VAZOES = 3


class TipoEstacao(IntEnum):
    """``tpEst`` values for ``HidroInventario``."""
    FLUVIOMETRICA = 1
    PLUVIOMETRICA = 2


class OrigemTelemetrica(IntEnum):
    """``origem`` values for ``ListaEstacoesTelemetricas``."""
    TODAS = 0
    ANA_INPE = 1
    ANA_SIVAM = 2
    RES_CONJ_03 = 3
    COTA_ONLINE = 4
    PROJETOS_ESPECIAIS = 5


def _s(name: str, required: bool = True) -> OperationParameter:
    t = xsd.resolve("string")
    if t is None:  # pragma: no cover — xsd:string is a built-in, always present
        raise RuntimeError("built-in xsd:string type is missing from the registry")
    return OperationParameter(name, t, required=required)


def _rows(fragment: str) -> list[dict[str, str | None]]:
    """Flatten a diffgram DataSet fragment into a list of row dicts.

    The fragment is an inline ``xsd:schema`` followed by a Microsoft diffgram
    whose DataSet holds one element per record. That row element is named *per
    operation* — ``Table`` for the catalogues / inventory / station registry,
    ``SerieHistorica`` for the historical series, ``DadosHidrometeorologicos``
    for telemetric data, and so on (the schema's ``msdata:MainDataTable``). So
    rows are taken generically as the children of the DataSet container inside
    the diffgram — never by a hard-coded table name, which would silently return
    nothing for the differently-named DataSets.

    Parsing goes through the hardened, XXE-safe parser; DataSet rows inherit the
    MRCS default namespace, so columns are read by local name.
    """
    root = parse_xml(f"<r>{fragment}</r>".encode())
    diffgram = next((e for e in root.iter() if local_name(e) == "diffgram"), None)
    if diffgram is None:
        return []
    out: list[dict[str, str | None]] = []
    for dataset in diffgram:
        # A SELECT result is just <NewDataSet>…</NewDataSet>; skip the optional
        # diffgr:before / diffgr:after change-tracking sections defensively.
        if local_name(dataset).lower() in ("before", "after"):
            continue
        for row in dataset:
            out.append({local_name(c): c.text for c in row})
    return out


@dataclass(frozen=True)
class SerieHistoricaRegistro:
    """One row of a ``HidroSerieHistorica`` DataSet.

    ``cod_estacao`` / ``data_hora`` are best-effort shortcuts (the exact column
    names vary per operation); the full, verbatim row is always in ``raw``.
    """
    cod_estacao: str | None
    data_hora: str | None
    raw: dict[str, str | None]


class AnaClient:
    """Client for the legacy ANA ServiceANA SOAP endpoint (12 operations)."""

    def __init__(
        self,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        transport: HttpTransport | None = None,
        soap_version: SoapVersion = SoapVersion.SOAP_11,
    ) -> None:
        self._client = SoapClient.manual(
            address=endpoint,
            binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
            soap_version=soap_version,
            transport=transport,
        )
        for sig in self._signatures():
            self._client.register_operation(sig)

    # -- operation registry ----------------------------------------------

    @staticmethod
    def _op(name: str, inputs: list[OperationParameter]) -> OperationSignature:
        return OperationSignature(
            name=name,
            soap_action=f"{ANA_NS}{name}",
            input_namespace=ANA_NS,
            output_namespace=ANA_NS,
            input_params=inputs,
            # The DataSet arrives inside <{name}Result>; required=False so a
            # legitimately empty result surfaces as AnaError, not a Server fault.
            output_params=[
                OperationParameter(f"{name}Result", AnyXmlType(),
                                   namespace=ANA_NS, required=False)
            ],
        )

    @classmethod
    def _signatures(cls) -> list[OperationSignature]:
        # Element names and order verified against the live .asmx envelopes.
        return [
            # -- telemetric data ----------------------------------------
            cls._op("DadosHidrometeorologicos", [
                _s("codEstacao"), _s("dataInicio"), _s("dataFim", required=False),
            ]),
            cls._op("DadosHidrometeorologicosGerais", [
                _s("codEstacao"), _s("dataInicio"), _s("dataFim", required=False),
            ]),
            # -- HIDRO catalogues -----------------------------------------
            cls._op("HidroBaciaSubBacia", [
                _s("codBacia", required=False), _s("codSubBacia", required=False),
            ]),
            cls._op("HidroEntidades", [_s("codEntidade", required=False)]),
            cls._op("HidroEstado", [_s("codUf", required=False)]),
            cls._op("HidroMunicipio", [_s("codMunicipio", required=False)]),
            cls._op("HidroRio", [_s("codRio", required=False)]),
            # -- inventory (12 filters, all optional; order matters) -------
            cls._op("HidroInventario", [
                _s("codEstDE", required=False), _s("codEstATE", required=False),
                _s("tpEst", required=False), _s("nmEst", required=False),
                _s("nmRio", required=False), _s("codSubBacia", required=False),
                _s("codBacia", required=False), _s("nmMunicipio", required=False),
                _s("nmEstado", required=False), _s("sgResp", required=False),
                _s("sgOper", required=False), _s("telemetrica", required=False),
            ]),
            # -- historical series ---------------------------------------
            cls._op("HidroSerieHistorica", [
                _s("codEstacao"), _s("dataInicio"), _s("dataFim", required=False),
                _s("tipoDados"), _s("nivelConsistencia"),
            ]),
            # -- telemetric station registry -----------------------------
            # NB: the docs say "Origem" but the wire element is lowercase.
            cls._op("ListaEstacoesTelemetricas", [
                _s("statusEstacoes", required=False), _s("origem", required=False),
            ]),
            # -- CotaOnline write ops (restricted; PascalCase elements) ---
            cls._op("IncluirDados_CotaOnline", [
                _s("Login"), _s("Senha"), _s("CodEstacao"), _s("DataHora"),
                _s("Chuva", required=False), _s("Cota", required=False),
                _s("Vazao", required=False),
            ]),
            cls._op("Excluir_CotaOnline", [
                _s("Login"), _s("Senha"), _s("CodEstacao"), _s("DataHora"),
            ]),
        ]

    # -- helpers ------------------------------------------------------------

    def _call_raw(self, op: str, **kwargs: Any) -> str:
        # A single AnyXmlType output param means call() returns the inner-XML
        # string directly (not a dict).
        frag = getattr(self._client.service, op)(**kwargs)
        if frag is None or frag == "":
            raise AnaServiceError(f"{op}: empty result from service")
        return str(frag)

    def _call_rows(self, op: str, **kwargs: Any) -> list[dict[str, str | None]]:
        rows = _rows(self._call_raw(op, **kwargs))
        # Some operations (e.g. DadosHidrometeorologicos) signal "no data for
        # this station/period" — or a rejected filter — not with an empty
        # DataSet or a SOAP fault, but with a single-row DataSet whose only
        # column is <Error>. Surface the service's own message as AnaError so a
        # caller never mistakes it for a data row.
        if len(rows) == 1 and set(rows[0]) == {"Error"}:
            raise AnaServiceError(f"{op}: {rows[0]['Error']}")
        return rows

    # -- public API: telemetric data --------------------------------------------

    def dados_hidrometeorologicos(
        self, cod_estacao: str, data_inicio: str, data_fim: str = "",
    ) -> list[dict[str, str | None]]:
        """Telemetric data for a station, with ANA-side filter validation.

        Dates as ``dd/mm/aaaa``.
        """
        return self._call_rows("DadosHidrometeorologicos",
                               codEstacao=cod_estacao,
                               dataInicio=data_inicio, dataFim=data_fim)

    def dados_hidrometeorologicos_gerais(
        self, cod_estacao: str, data_inicio: str, data_fim: str = "",
    ) -> list[dict[str, str | None]]:
        """Raw telemetric data as transmitted by stations (no filter validation)."""
        return self._call_rows("DadosHidrometeorologicosGerais",
                               codEstacao=cod_estacao,
                               dataInicio=data_inicio, dataFim=data_fim)

    # -- public API: HIDRO catalogues ---------------------------------------------

    def hidro_estado(self, cod_uf: str = "") -> list[dict[str, str | None]]:
        """States (UF); empty ``cod_uf`` returns all."""
        return self._call_rows("HidroEstado", codUf=cod_uf)

    def hidro_municipio(self, cod_municipio: str = "") -> list[dict[str, str | None]]:
        """Municipalities; empty code returns all."""
        return self._call_rows("HidroMunicipio", codMunicipio=cod_municipio)

    def hidro_rio(self, cod_rio: str = "") -> list[dict[str, str | None]]:
        """Rivers; empty code returns all."""
        return self._call_rows("HidroRio", codRio=cod_rio)

    def bacias(
        self, cod_bacia: str = "", cod_sub_bacia: str = "",
    ) -> list[dict[str, str | None]]:
        """Basins and sub-basins; empty codes return all."""
        return self._call_rows("HidroBaciaSubBacia",
                               codBacia=cod_bacia, codSubBacia=cod_sub_bacia)

    def entidades(self, cod_entidade: str = "") -> list[dict[str, str | None]]:
        """Entities responsible for / operating stations; empty code returns all."""
        return self._call_rows("HidroEntidades", codEntidade=cod_entidade)

    # -- public API: inventory & station registry --------------------------------

    def inventario(
        self,
        *,
        cod_est_de: str = "", cod_est_ate: str = "",
        tp_est: TipoEstacao | int | str = "",
        nm_est: str = "", nm_rio: str = "",
        cod_sub_bacia: str = "", cod_bacia: str = "",
        nm_municipio: str = "", nm_estado: str = "",
        sg_resp: str = "", sg_oper: str = "",
        telemetrica: str = "",
    ) -> list[dict[str, str | None]]:
        """Station inventory (pluviometric/fluviometric); all filters optional."""
        tp = str(int(tp_est)) if isinstance(tp_est, (TipoEstacao, int)) else tp_est
        return self._call_rows(
            "HidroInventario",
            codEstDE=cod_est_de, codEstATE=cod_est_ate,
            tpEst=tp, nmEst=nm_est, nmRio=nm_rio,
            codSubBacia=cod_sub_bacia, codBacia=cod_bacia,
            nmMunicipio=nm_municipio, nmEstado=nm_estado,
            sgResp=sg_resp, sgOper=sg_oper, telemetrica=telemetrica,
        )

    def estacoes_telemetricas(
        self,
        status: str = "0",
        origem: OrigemTelemetrica | int | str = OrigemTelemetrica.TODAS,
    ) -> list[dict[str, str | None]]:
        """Registered telemetric stations (``status``: 0-Ativo, 1-Manutenção)."""
        org = str(int(origem)) if isinstance(origem, (OrigemTelemetrica, int)) else origem
        return self._call_rows("ListaEstacoesTelemetricas",
                               statusEstacoes=status, origem=org)

    # -- public API: historical series --------------------------------------------

    def serie_historica(
        self,
        cod_estacao: str,
        data_inicio: str,
        *,
        data_fim: str = "",
        tipo_dados: TipoDados | int = TipoDados.VAZOES,
        nivel_consistencia: int = 1,
    ) -> list[SerieHistoricaRegistro]:
        """Historical series — dates ``dd/mm/aaaa``; consistency 1-Bruto, 2-Consistido."""
        rows = self._call_rows(
            "HidroSerieHistorica",
            codEstacao=cod_estacao, dataInicio=data_inicio, dataFim=data_fim,
            tipoDados=str(int(tipo_dados)),
            nivelConsistencia=str(nivel_consistencia),
        )
        return [
            SerieHistoricaRegistro(
                cod_estacao=r.get("EstacaoCodigo"),
                data_hora=r.get("DataHora"),
                raw=r,
            )
            for r in rows
        ]

    # -- public API: CotaOnline write operations (restricted) ---------------------

    def incluir_cota_online(
        self,
        login: str, senha: str, cod_estacao: str, data_hora: str,
        *,
        chuva: str = "", cota: str = "", vazao: str = "",
    ) -> str:
        """Insert CotaOnline data (restricted to registered partners).

        Credentials travel plaintext in the SOAP body — this is the service's
        design, not ours; only call over HTTPS.
        """
        return self._call_raw(
            "IncluirDados_CotaOnline",
            Login=login, Senha=senha, CodEstacao=cod_estacao,
            DataHora=data_hora, Chuva=chuva, Cota=cota, Vazao=vazao,
        )

    def excluir_cota_online(
        self, login: str, senha: str, cod_estacao: str, data_hora: str,
    ) -> str:
        """Delete CotaOnline data (restricted to registered partners)."""
        return self._call_raw(
            "Excluir_CotaOnline",
            Login=login, Senha=senha, CodEstacao=cod_estacao, DataHora=data_hora,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AnaClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
