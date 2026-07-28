# soapbar

A SOAP library for Python — client, server, and WSDL handling.

soapbar implements SOAP 1.1 and 1.2 with all five binding styles, auto-generates WSDL from Python service classes, parses existing WSDL to drive a typed client, and integrates with any ASGI or WSGI framework via thin adapter classes. The XML parser is hardened against XXE attacks using lxml with `resolve_entities=False`.

> **Conformance** — soapbar ships with an internal conformance suite of **116 tests across 11 spec-mapped classes** ([`tests/audit/test_compliance.py`](https://github.com/hitoshyamamoto/soapbar/blob/main/tests/audit/test_compliance.py)) covering SOAP 1.1/1.2, WSDL 1.1, and WS-I Basic Profile 1.1 — including the WS-I BSP X.509 token profile — and the gaps found by earlier internal audits; all pass. This is a self-administered test suite, not an independent third-party audit.

---

## Features

- SOAP 1.1 and 1.2 (auto-detected from envelope namespace; fault codes auto-translated)
- All 5 WSDL/SOAP binding style combinations (RPC/Encoded, RPC/Literal, Document/Literal, Document/Literal/Wrapped, Document/Encoded)
- Auto-generates WSDL from service class definitions — no config files needed
- Parses existing WSDL to drive a typed client
- ASGI adapter (`AsgiSoapApp`) and WSGI adapter (`WsgiSoapApp`)
- XXE-safe hardened XML parser (lxml, `resolve_entities=False`, `no_network=True`, `load_dtd=False`)
- Message size limit (10 MB default) and XML nesting depth limit (100 levels) — DoS protection
- Continuously assured: CodeQL static analysis and property-based tests (Hypothesis) on every pull request, coverage-guided fuzzing (Atheris) weekly; holds the [OpenSSF Best Practices passing badge](https://www.bestpractices.dev/projects/13849) — see [Security](security.md)
- **WS-Security UsernameToken** — PasswordText and PasswordDigest (SHA-1) on both client and server
- **XML Signature** — enveloped XML-DSIG signing and verification (`sign_envelope` / `verify_envelope`, requires `signxml`)
- **Id-targeted signing** — sign an inner element selected by its `Id`/Reference URI (`sign_element_by_id`), with a configurable algorithm set (incl. the SEFAZ NF-e RSA-SHA1 / inclusive-C14N / EndCertOnly profile)
- **XML Encryption** — AES-256-GCM authenticated body encryption with RSA-OAEP session-key wrapping (`encrypt_body` / `decrypt_body`, requires `cryptography`)
- **MTOM/XOP** — send and receive SOAP messages with binary attachments; `SoapClient(use_mtom=True)` + `add_attachment()`; server decodes inbound MTOM automatically
- **WSDL schema validation** — opt-in Body validation against WSDL-embedded XSD types (`SoapApplication(validate_body_schema=True)`)
- **One-way MEP** — `@soap_operation(one_way=True)` returns HTTP 202 with empty body
- **SOAP array attributes** — `enc:itemType`/`enc:arraySize` (SOAP 1.2) and `SOAP-ENC:arrayType` (SOAP 1.1) emitted automatically
- **Multi-reference encoding** — shared complex objects serialized with `id`/`href` per SOAP 1.1 §5.2.5
- **rpc:result** — opt-in `@soap_operation(emit_rpc_result=True)` per SOAP 1.2 Part 2 §4.2.1
- WS-Addressing 1.0 — MessageID, RelatesTo, Action, ReferenceParameters propagated in responses
- XSD type registry with 27 built-in types
- Sync and async HTTP client (httpx optional)
- **Mutual TLS** — client certificates + custom CA bundle (`HttpTransport(client_cert=…, ca_bundle=…)`), with a PKCS#12 helper (`load_pkcs12`) for ICP-Brasil A1 `.pfx`
- **Session cookies** — persisted across calls (`HttpTransport(persist_cookies=True)`) for stateful services; read/inject via `transport.cookies`
- **Document/literal *bare* + `xsd:any`** — passes raw XML through a single body element (e.g. NF-e's `nfeDadosMsg`)
- **Real-world clients** — optional typed clients under `soapbar.contrib.*`: EU VIES (`ViesClient`), WITSML 1.4.1.1 (`WitsmlClient`), SEFAZ NF-e (`NfeClient`), ANA ServiceANA (`AnaClient`)
- Interoperable with zeep and spyne out-of-the-box (verified by integration tests; the spyne suite runs on Python ≤ 3.11, as upstream spyne does not import on 3.12+)
- **JSON dual-mode** — any SOAP endpoint returns JSON when client sends `Accept: application/json`; no separate endpoint needed
- **Non-strict WSDL parsing** — `parse_wsdl(..., strict=False)` silently skips unresolvable imports instead of raising
- Full type annotations + `py.typed` marker (PEP 561)
- Python 3.10 – 3.14

---

## Installation

```bash
pip install soapbar              # core + server + WSDL (lxml only)
pip install soapbar[core]        # explicit alias for the above
pip install soapbar[server]      # explicit alias for the above
pip install soapbar[client]      # + httpx for the HTTP client
pip install soapbar[security]    # + signxml + cryptography (XML Sig/Enc, mutual TLS)
pip install soapbar[all]         # everything (client + security)

# Real-world contrib clients (see "Real-world services"):
pip install soapbar[vies]        # EU VIES VAT validation
pip install soapbar[witsml]      # WITSML 1.4.1.1 STORE
pip install soapbar[ana]         # ANA ServiceANA (Brazilian water telemetry)
pip install soapbar[nfe]         # SEFAZ NF-e (mutual TLS + signing)
```

Or with uv:

```bash
uv add soapbar
uv add "soapbar[client]"
uv add "soapbar[security]"
uv add "soapbar[all]"
uv add "soapbar[nfe]"            # or [vies] / [witsml] / [ana]
```

---

## Inspired by

- **[Spyne](https://github.com/arskom/spyne)** — the original comprehensive Python SOAP/RPC framework; inspired the service-class model and binding style abstractions.
- **[zeep](https://github.com/mvantellingen/python-zeep)** — the de facto modern Python SOAP client; inspired the WSDL-driven client approach and XSD type mapping.
- **[fastapi-soap](https://github.com/rezashahnazar/fastapi-soap)** — demonstrated clean FastAPI/ASGI integration for SOAP endpoints; inspired the ASGI adapter design.

---

## Learn more

**SOAP protocol**

- [Wikipedia — SOAP](https://pt.wikipedia.org/wiki/SOAP)
- [W3Schools — XML/SOAP intro](https://www.w3schools.com/XML/)
- [GeeksForGeeks — Basics of SOAP](https://www.geeksforgeeks.org/computer-networks/basics-of-soap-simple-object-access-protocol/)
- [Oracle — SOAP API reference](https://docs.oracle.com/en/cloud/saas/applications-common/25a/biacc/soap-api.html)

**WSDL**

- [TutorialsPoint — WSDL](https://www.tutorialspoint.com/wsdl/index.htm)
- [GeeksForGeeks — WSDL introduction](https://www.geeksforgeeks.org/software-engineering/wsdl-introduction/)

**Binding styles and encoding**

- [IBM developerWorks — Which WSDL style?](https://developer.ibm.com/articles/ws-whichwsdl/)
- [DZone — Different SOAP encoding styles](https://dzone.com/articles/different-soap-encoding-styles)
- [Stack Overflow — Document vs RPC style](https://stackoverflow.com/questions/9062475/what-is-the-difference-between-document-style-and-rpc-style-communication)
