# soapbar

[![CI](https://github.com/hitoshyamamoto/soapbar/actions/workflows/push.yml/badge.svg?branch=main)](https://github.com/hitoshyamamoto/soapbar/actions/workflows/push.yml)
[![PyPI](https://img.shields.io/pypi/v/soapbar.svg?logo=pypi&logoColor=white)](https://pypi.org/project/soapbar/)
[![Python versions](https://img.shields.io/pypi/pyversions/soapbar.svg?logo=python&logoColor=white)](https://pypi.org/project/soapbar/)
[![Downloads](https://img.shields.io/pypi/dm/soapbar.svg?logo=pypi&logoColor=white)](https://pypi.org/project/soapbar/)
[![GitHub stars](https://img.shields.io/github/stars/hitoshyamamoto/soapbar.svg?logo=github&logoColor=white)](https://github.com/hitoshyamamoto/soapbar/stargazers)
[![License](https://img.shields.io/pypi/l/soapbar.svg)](https://github.com/hitoshyamamoto/soapbar/blob/main/LICENSE)
[![Conformance suite](https://img.shields.io/badge/conformance%20suite-116%20tests-blue)](https://github.com/hitoshyamamoto/soapbar/blob/main/tests/audit/test_compliance.py)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hitoshyamamoto/soapbar/badge)](https://scorecard.dev/viewer/?uri=github.com/hitoshyamamoto/soapbar)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13849/badge)](https://www.bestpractices.dev/projects/13849)

A SOAP library for Python — client, server, and WSDL handling.

soapbar implements SOAP 1.1 and 1.2 with all five binding styles, auto-generates WSDL from Python service classes, parses existing WSDL to drive a typed client, and integrates with any ASGI or WSGI framework via thin adapter classes. The XML parser is hardened against XXE attacks using lxml with `resolve_entities=False`.

> **Conformance** — soapbar ships with an internal conformance suite of **116 tests across 11 spec-mapped classes** (`tests/audit/test_compliance.py`) covering SOAP 1.1/1.2, WSDL 1.1, and WS-I Basic Profile 1.1 — including the WS-I BSP X.509 token profile — and the gaps found by earlier internal audits; all pass. This is a self-administered test suite, not an independent third-party audit.

---

## Documentation

**Full documentation lives at [hitoshyamamoto.github.io/soapbar](https://hitoshyamamoto.github.io/soapbar/)** — quick start, client and server guides, WS-Security, MTOM, real-world service clients, architecture, and more.

---

## Installation

```bash
pip install soapbar              # core + server + WSDL (lxml only)
pip install soapbar[client]      # + httpx for the HTTP client
pip install soapbar[security]    # + signxml + cryptography (XML Sig/Enc, mutual TLS)
pip install soapbar[all]         # everything (client + security)
```

Or with uv:

```bash
uv add soapbar
uv add "soapbar[client]"
uv add "soapbar[security]"
uv add "soapbar[all]"
```

Optional contrib extras install typed clients for real-world services: `soapbar[vies]`, `soapbar[witsml]`, `soapbar[ana]`, `soapbar[nfe]` — see [Real-world services](https://hitoshyamamoto.github.io/soapbar/real-world/).

---

## Quick start — server

```python
# app.py
from soapbar import SoapService, soap_operation, SoapApplication, AsgiSoapApp


class CalculatorService(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calculator"

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation()
    def subtract(self, a: int, b: int) -> int:
        return a - b


soap_app = SoapApplication(service_url="http://localhost:8000")
soap_app.register(CalculatorService())

app = AsgiSoapApp(soap_app)
# Run: uvicorn app:app --port 8000
# WSDL: GET http://localhost:8000?wsdl
```

Mounting inside FastAPI/Flask, defining services, and binding styles are covered in the [Quick start](https://hitoshyamamoto.github.io/soapbar/quickstart/) docs.

---

## Quick start — client

Drive a typed client from an existing WSDL:

```python
from soapbar import SoapClient

client = SoapClient(wsdl_url="http://localhost:8000?wsdl")
result = client.service.add(a=3, b=5)     # or client.call("add", a=3, b=5)
```

Async (`await client.call_async(...)`), WSDL-less `SoapClient.manual(...)`, mutual TLS (`HttpTransport(client_cert=..., ca_bundle=...)`, `load_pkcs12(...)`), and session cookies are covered in the [Client](https://hitoshyamamoto.github.io/soapbar/client/) docs.

---

## Features

- SOAP 1.1 and 1.2 with all 5 WSDL/SOAP binding style combinations; version auto-detected, fault codes auto-translated
- SOAP server for any ASGI or WSGI framework (`AsgiSoapApp` / `WsgiSoapApp`), plus a sync and async WSDL-driven client
- Auto-generates WSDL from service classes and parses existing WSDL — no config files needed
- Hardened by default: XXE-safe lxml parser, SSRF guard on `wsdl:import`, message size and nesting depth limits, error scrubbing
- Continuously assured: CodeQL static analysis and property-based tests (Hypothesis) on every pull request, coverage-guided fuzzing (Atheris) weekly; holds the [OpenSSF Best Practices passing badge](https://www.bestpractices.dev/projects/13849)
- WS-Security: UsernameToken (PasswordText/PasswordDigest), XML Signature (incl. Id-targeted SEFAZ NF-e profile), AES-256-GCM XML Encryption, WS-I BSP X.509 token profile
- MTOM/XOP binary attachments on both client and server
- Mutual TLS with PKCS#12 helper, session cookies, WS-Addressing 1.0, one-way MEP, opt-in WSDL schema validation
- XSD type registry (27 built-in types), complex types, SOAP arrays, multi-reference encoding
- Optional typed clients for real-world services: EU VIES, WITSML, SEFAZ NF-e, ANA (`soapbar.contrib.*`)
- Interoperable with zeep and spyne (the spyne suite runs on Python ≤ 3.11 — upstream spyne does not import on 3.12+); fully type-annotated (PEP 561); Python 3.10 – 3.14

---

## Links

- [Documentation](https://hitoshyamamoto.github.io/soapbar/)
- [Security](https://hitoshyamamoto.github.io/soapbar/security/) — hardened parser, WS-Security, XML Signature and Encryption
- [Security assurance case](https://hitoshyamamoto.github.io/soapbar/assurance-case/) — threat model, trust boundaries, residual risk
- [Security policy](https://github.com/hitoshyamamoto/soapbar/blob/main/.github/SECURITY.md) — private vulnerability reporting, supported versions, response times
- [Verifying a release](https://hitoshyamamoto.github.io/soapbar/security/#verifying-a-release) — Sigstore provenance and SBOM
- [Real-world services](https://hitoshyamamoto.github.io/soapbar/real-world/) — VIES, NF-e, WITSML, ANA, IRS MeF
- [Comparison with alternatives](https://hitoshyamamoto.github.io/soapbar/comparison/) — zeep, spyne, fastapi-soap, and why most other Python SOAP libraries are no longer actively released
- [Stability policy](https://github.com/hitoshyamamoto/soapbar/blob/main/STABILITY.md) — public surface, SemVer, deprecation process
- [Roadmap](https://github.com/hitoshyamamoto/soapbar/blob/main/ROADMAP.md) — what is planned, and what is deliberately not
- [Governance](https://github.com/hitoshyamamoto/soapbar/blob/main/GOVERNANCE.md) — decision model, roles, continuity

---

## Sponsoring

soapbar is maintained by a single developer. If your organization depends on it — or on SOAP integrations with services such as VIES, NF-e, WITSML, or ANA — consider sponsoring its maintenance:

- [GitHub Sponsors](https://github.com/sponsors/hitoshyamamoto)
- The repository publishes a machine-readable funding manifest for the [FLOSS/fund](https://floss.fund) directory

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
