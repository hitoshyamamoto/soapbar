# Changelog

All notable changes to soapbar are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

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
