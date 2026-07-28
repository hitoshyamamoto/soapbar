# Real-world services

soapbar is exercised against actual government/industry SOAP services. Runnable
demonstrations live under [`examples/`](https://github.com/hitoshyamamoto/soapbar/tree/main/examples),
and optional typed clients ship under `soapbar.contrib.*` (installable via extras).

| Service | Binding | Auth | Example | Client |
|---|---|---|---|---|
| EU VIES (VAT validation) | document/literal, SOAP 1.1 | none | [`17_vies/`](https://github.com/hitoshyamamoto/soapbar/tree/main/examples/17_vies/) | `soapbar.contrib.vies` (`soapbar[vies]`) |
| WITSML 1.4.1.1 STORE | RPC | WS-Security UsernameToken | [`18_witsml/`](https://github.com/hitoshyamamoto/soapbar/tree/main/examples/18_witsml/) | `soapbar.contrib.witsml` (`soapbar[witsml]`) |
| SEFAZ NF-e | document/literal bare, SOAP 1.2 | mutual TLS (ICP-Brasil) + `<infNFe>` `Id`-signing | [`19_nfe/`](https://github.com/hitoshyamamoto/soapbar/tree/main/examples/19_nfe/) | `soapbar.contrib.nfe` (`soapbar[nfe]`) |
| IRS MeF (A2A) | SOAP/HTTP, session-based | mutual TLS (Strong Auth) + session cookies | [`20_mef/`](https://github.com/hitoshyamamoto/soapbar/tree/main/examples/20_mef/) | *(use the core APIs directly)* |
| ANA ServiceANA (telemetria hidrometeorológica) | document/literal wrapped, SOAP 1.1/1.2 (`.asmx`) | none (CotaOnline writes: body credentials) | [`21_ana/`](https://github.com/hitoshyamamoto/soapbar/tree/main/examples/21_ana/) | `soapbar.contrib.ana` (`soapbar[ana]`) |

The VIES, WITSML and ANA examples run against live endpoints; the NF-e and MeF
examples are faithful references (their `main()` prints guidance without
network access).

```python
from soapbar.contrib.vies import ViesClient

with ViesClient() as vies:                  # WSDL is bundled — no network to construct
    result = vies.check_vat("BE", "0203201340")
    print(result.valid, result.name, result.address)
```

## Live homologation & secrets

The contrib clients are validated two ways: offline against the canonical
service definitions (bundled/canonical WSDLs, the SEFAZ signing standard), and
by `live`-marked tests that exercise real endpoints. Live tests are deselected
from the normal suite — run them with `scripts/live.sh` (or `pytest -m live`),
and any whose credentials are absent **skip**. How each is credentialed reflects
how sensitive its inputs are:

| Service | Live status | Endpoint / credentials |
|---|---|---|
| **VIES** | **live-homologated** (CI `live.yml` + locally) | the EC deterministic **test** service `…/checkVatTestService` (a *different* endpoint+WSDL from the bundled production one, via `endpoint=`): VAT `100`→valid, `200`→invalid, and `201`/`300`/`301`/`302` drive the full fault→exception map. No secrets. |
| **WITSML** | offline + canonical-WSDL validated; **live-runnable, not yet homologated** | a **test account** against a non-production server via `WITSML_URL` / `WITSML_USER` / `WITSML_PASSWORD` — best kept in a protected GitHub **Environment** secret. Skips when unset (so it's *unverified* on forks / unconfigured clones). |
| **NF-e** | offline + signing-conformance validated; **run locally only** | an ICP-Brasil **homologação** certificate via `NFE_PFX` / `NFE_PFX_PASSWORD` / `NFE_STATUS_URL` / `NFE_UF`. |

```bash
# Local homologation — credentials in a gitignored .env.live (or your shell):
scripts/live.sh                              # all live tests; uncredentialed ones skip
scripts/live.sh tests/test_contrib_vies.py   # just VIES (no secrets needed)
```

**Security:** the NF-e certificate is a private key (a real cryptographic
identity tied to a CNPJ, even in homologação) — keep it on your own machine and
run NF-e homologation **locally**; do not upload it to CI. If you ever must, use
a *homologação* certificate only (never production), in a protected GitHub
Environment, decoded at runtime. `live.yml` runs only on schedule and
`workflow_dispatch` (never on PRs, so fork PRs can't reach secrets);
`.env.live`, `*.pfx`, `*.p12`, and `*.pem` are gitignored.
