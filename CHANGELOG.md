# Changelog

All notable changes to soapbar are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.4.2] — 2026-04-11

### Fixed

- **N01** `wssecurity.py` — `build_security_header()` now accepts a `soap_ns` parameter and
  sets `{soap_ns}mustUnderstand="1"` on the `wsse:Security` element when provided, as required
  by WS-Security 1.0 §6.1. Both `SoapClient.call()` and `call_async()` pass the envelope
  namespace so every outbound Security header is correctly marked.
- **N02** `fault.py` — SOAP 1.1 `faultcode` is now serialised as a namespace-qualified QName
  (`soapenv:Client`, `soapenv:Server`, etc.) per SOAP 1.1 §4.4. The parser strips the prefix
  on read-back so `SoapFault.faultcode` remains the unqualified canonical name internally.
- **N03** `envelope.py` — `mustUnderstand` parsing is now version-aware: SOAP 1.1 §4.2.1
  accepts only `"1"`; SOAP 1.2 §5.2.1 additionally accepts `"true"`.
- **N04** `application.py` — SOAP 1.2 MustUnderstand fault responses now include one
  `soap12:NotUnderstood` header block per unrecognised mandatory header (previously at most
  one block was emitted).
- **N08** `wssecurity.py` — `extract_certificate_from_security()` validates the decoded X.509
  certificate's validity window (`not_valid_before_utc` / `not_valid_after_utc`) and raises
  `XmlSecurityError` if the certificate is expired or not yet valid.
- **N10** `client.py` — `call_async()` now injects the WS-Security credential header, matching
  the behaviour of `call()` (credential was silently dropped in the async path).
- **N12** `wsgi.py` — One-way MEP responses now return `"202 Accepted"` instead of the
  incorrect `"202 Error"` HTTP status line.
- **N13** `xml.py` — `check_xml_depth()` iterparse now passes `load_dtd=False` and
  `no_network=True`, closing a gap between the depth-check path and the main hardened parser.

### Changed

- **N01** `application.py` — `mustUnderstand` enforcement now whitelists understood namespaces
  before raising a fault: WS-Addressing (`NS.WSA`) is always whitelisted; WS-Security
  (`NS.WSSE`) is whitelisted when a `security_validator` is configured. Unknown mandatory
  headers are collected before the fault is raised, enabling full multi-header reporting.

---

## [0.4.1] — 2026-04-08

### Added
- WS-I BSP 1.1 X.509 token profile (S10): `build_binary_security_token`,
  `extract_certificate_from_security`, `sign_envelope_bsp`, `verify_envelope_bsp`
- `__version__` now derived from package metadata via `importlib.metadata`

### Fixed
- Redundant loop in `SoapApplication._get_compiled_schema()` (B007)

### Changed
- Minimum Python version documented as >=3.12 (3.10/3.11 dropped since 0.3.0)

---

## [0.4.0] — 2026-03-xx

### Added
- MTOM/XOP multipart SOAP message support: `parse_mtom`, `build_mtom`,
  `MtomAttachment`, `MtomMessage` (I01)
- XML Signature and Encryption: `sign_envelope`, `verify_envelope`,
  `encrypt_body`, `decrypt_body`, `build_security_header`,
  `UsernameTokenCredential`, `UsernameTokenValidator` (I03)
- WSDL inline schema validation of SOAP Body content: `compile_schema`,
  `validate_schema`; `SoapApplication(validate_body_schema=True)` (X07)

---

## [0.3.0] — 2026-02-xx

### Added
- WS-I BP R1109 HTTP 500 for all SOAP faults
- One-way MEP (operations with no return value)
- SOAP-ENC array attributes (G05/G06)
- Multi-ref serialization (G09)
- `rpc:result` opt-in via `@soap_operation(emit_rpc_result=True)` (G10)
- WS-Security UsernameToken header support

---

## [0.2.0] — 2026-01-xx

### Added
- Full SOAP 1.1 and 1.2 envelope parsing and building
- SOAP Fault (1.1 and 1.2) with subcodes
- WSDL 1.1 parser and builder
- WS-Addressing 1.0 request/response headers
- Input parameter validation (F09)
- Remote WSDL import block by default (I04 SSRF guard)
- WSGI and ASGI adapters

---

## [0.1.0] — 2025-xx-xx

### Added
- Initial release: SOAP 1.1 server scaffold, basic RPC/Document binding,
  lxml hardened parser (XXE, Billion Laughs, SSRF prevention)
