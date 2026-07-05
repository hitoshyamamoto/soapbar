"""
examples/21_ana/ana_demo.py — Consume ANA's ServiceANA water-telemetry SOAP service with soapbar.

READY CLIENT
    Prefer the typed `soapbar.contrib.ana.AnaClient` (`soapbar[ana]`) — it
    registers all 12 operations, flattens the ADO.NET DataSet the service
    returns into plain dict rows, and encodes the contract quirks. This script
    drives that client against the live, public endpoint.

WHAT THIS DEMONSTRATES
    Pointing soapbar at a classic Microsoft `.asmx` SOAP service — document /
    literal *wrapped*, namespace `http://MRCS/`, quoted SOAPAction — with no
    authentication for the read operations, and reading back the Microsoft
    diffgram DataSet as ordinary rows.

SERVICE FACTS (verified against the live endpoint)
    Endpoint  : https://telemetriaws1.ana.gov.br/ServiceANA.asmx
    Binding   : document / literal wrapped, SOAP 1.1/1.2, quoted SOAPAction
    Namespace : http://MRCS/
    Reads     : DadosHidrometeorologicos, the five HIDRO catalogues,
                HidroInventario (12 filters), HidroSerieHistorica,
                ListaEstacoesTelemetricas — all no-auth.
    Writes    : IncluirDados_CotaOnline / Excluir_CotaOnline — restricted to
                registered partners, plaintext credentials in the body.

CONTRACT QUIRKS (handled by the client)
    * ListaEstacoesTelemetricas: the wire element is lowercase `origem`.
    * CotaOnline writes use PascalCase elements, unlike every read op.
    * Responses are an inline xsd:schema + Microsoft diffgram; rows inherit the
      MRCS default namespace (the client matches them by local name).

LEGACY NOTICE
    ANA announced this service's discontinuation (superseded by the REST
    Hidro_Webservice); it remains online but should be treated as legacy.

REQUIREMENTS
    `soapbar[ana]` (httpx). Network access to telemetriaws1.ana.gov.br.

Run:
    uv run python examples/21_ana/ana_demo.py

NOTE
    The exact DataSet column names vary per operation; this demo prints whole
    rows (dicts) rather than assuming field names.
"""

from __future__ import annotations

from soapbar.contrib.ana import AnaClient, AnaError, TipoDados

# A well-known fluviometric station on the Rio das Velhas (MG); substitute any
# station code you want to query.
DEMO_STATION = "61135000"


def main() -> None:
    with AnaClient() as ana:
        try:
            estacoes = ana.estacoes_telemetricas(status="0")
        except AnaError as exc:
            print(f"ListaEstacoesTelemetricas failed: {exc}")
            return
        except Exception as exc:
            print(f"Could not reach ServiceANA ({type(exc).__name__}): {exc}")
            return

        print(f"Active telemetric stations returned: {len(estacoes)}")
        if estacoes:
            print("  first row:", estacoes[0])

        # A catalogue call — always populated (the ~27 Brazilian states, plus
        # historical/aggregate codes). Empty filters return the whole catalogue.
        estados = ana.hidro_estado()
        print(f"\nStates catalogue (HidroEstado): {len(estados)} rows")
        for uf in estados[:3]:
            print("  ", uf)

        # Historical series (flow rates) for the demo station, first half of 2026.
        try:
            serie = ana.serie_historica(
                cod_estacao=DEMO_STATION,
                data_inicio="01/01/2026",
                data_fim="30/06/2026",
                tipo_dados=TipoDados.VAZOES,
                nivel_consistencia=1,
            )
        except AnaError as exc:
            print(f"HidroSerieHistorica returned nothing for {DEMO_STATION}: {exc}")
            return

        print(f"\nHidroSerieHistorica rows for station {DEMO_STATION}: {len(serie)}")
        for reg in serie[:3]:
            print("  ", reg.data_hora, "->", reg.raw)


if __name__ == "__main__":
    main()
