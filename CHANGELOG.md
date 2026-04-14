# Changelog

All notable changes to soapbar are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.6.3] — 2026-04-14

### Fixed (CRITICAL)

- **`SoapClient(wsdl_url=…)` now actually drives the call.** A bug
  present since the WSDL-driven client landed: `_init_from_wsdl` parsed
  the WSDL and set `_address`, `_binding_style`, and `_soap_version`
  but never iterated `binding.operations` and never called
  `register_operation(...)`. `client._signatures` therefore stayed `{}`
  after any `SoapClient(wsdl_url=…)`, `SoapClient.from_file(...)`, or
  `SoapClient.from_wsdl_string(...)` load. Subsequent
  `client.call("Op", **kwargs)` fell through to `_get_sig()`'s bare
  fallback, the serializer emitted an empty wrapper, and every kwarg
  was silently dropped on the wire. Against soapbar↔soapbar this
  surfaced as `Client` fault `"Missing required input parameter(s): …"`;
  against permissive third-party servers it delivered empty calls.
  `_init_from_wsdl` now walks `port_types` and `messages` to register
  one `OperationSignature` per binding operation, resolving
  `part.element` (document-literal) or `part.type` (RPC) into
  `OperationParameter`s. DOCUMENT_LITERAL_WRAPPED is auto-detected from
  the message shape (one part with `element=` whose local-name matches
  the operation name, per WS-I BP R2201 + R2204).
- **DLW deserializer tolerates namespace-less signatures.**
  `DocumentLiteralWrappedSerializer._extract_params` now falls back to
  a local-name match across any namespace when qualified and
  unqualified finds both miss. Makes the common server-side case
  (`@soap_operation` without explicit `input_namespace`) able to read
  the qualified wire that the WSDL-driven client emits.

### Added

- **16-example directory restructure under `examples/`** — numbered,
  feature-focused folders keyed to specific audit IDs. Each example
  is self-contained, binds to `127.0.0.1` only, and ships its own
  `uv run …` invocation in its module docstring. See
  `examples/README.md` for the index.
- **`TestWsdlDrivenClientCall` in `tests/test_soapbar.py`** — the
  first test class that exercises `SoapClient.from_wsdl_string(...) →
  client.call(...)` end-to-end. Three cases: DLW round-trip,
  RPC/Literal round-trip, and a signature-registration assertion that
  pins the fix so the bug cannot silently come back.

---

## [0.6.2] — 2026-04-14

### Added

- **`xsd:import` and `xsd:include` resolution inside `<wsdl:types>`** —
  `parse_wsdl` now walks these elements recursively, fetching each
  referenced schema via the existing SSRF-guarded `_fetch_wsdl_source`
  and merging the harvested complex types into the type registry.
  Before 0.6.2 they were silently ignored (documented as a known
  limitation in the README), which broke the first real enterprise
  WSDL (SAP, Salesforce partner, NF-e) whose contracts typically span
  two to four schema files. Cycle detection via a scoped resolved-URL
  set; recursion capped at 8 levels via `_MAX_XSD_IMPORT_DEPTH`; the
  `allow_remote_imports` and `strict` flags apply uniformly to
  `xsd:import` and `wsdl:import`
- **`tests/wsdl_samples/multi_schema/`** — fixture WSDL + two-hop
  schema chain (`crm.wsdl` → `types.xsd` → `common.xsd`) modelled on
  the shape of real enterprise SOAP contracts
- **`tests/wsdl_samples/circular_schema/`** — fixture WSDL + two
  cross-importing schemas (`a.xsd` ⇄ `b.xsd`) exercising cycle
  detection
- **`tests/test_real_wsdls.py::TestMultiSchemaWsdl`** — integration
  tests for the multi-schema fixture, asserting both direct and
  transitive imports produce registered complex types
- **`tests/test_soapbar.py::TestXsdImportResolution`** — unit tests
  covering multi-file resolution, circular imports, SSRF guard on
  remote `xsd:import`, and the `allow_remote_imports` opt-in
- **GitHub Release on tag push** — `.github/workflows/release.yml`
  gains a `github-release` job that extracts the matching CHANGELOG
  section via `awk` and publishes a GitHub Release via
  `softprops/action-gh-release@v3.0.0` (SHA-pinned). Previous tags
  shipped to PyPI but produced no GitHub Release; `latestRelease` was
  `null` despite 8 tags

### Fixed

- **`xsd` registry leak from WSDL-parsing tests** — both new test
  classes (`TestXsdImportResolution`,
  `TestMultiSchemaWsdl`) snapshot and restore the global xsd registry
  around each test, matching the pattern commit `6ec36a1` applied to
  the spyne WSDL-parse test. Prevents test-order pollution from
  breaking the 27-types invariant asserted elsewhere in the suite

---

## [0.6.1] — 2026-04-14

### Added

- **`SoapApplication(enable_gzip=True)`** — opt-in HTTP-level gzip on
  the WSGI and ASGI adapters. Inbound bodies carrying
  `Content-Encoding: gzip` are transparently decompressed before SOAP
  dispatch; outbound responses are gzip-compressed when the client
  advertises `Accept-Encoding: gzip` (with the corresponding
  `Content-Encoding: gzip` response header). Default is off to
  preserve bit-identical pre-0.6.1 behavior. Helper module
  `soapbar.server._compression` exposes the wrapped gzip primitives
- **`HttpTransport.close()`**, **`HttpTransport.aclose()`**, and
  context-manager support (`__enter__` / `__exit__`) — release the
  pooled `httpx.Client` / `httpx.AsyncClient` that the transport now
  reuses across requests (see *Changed* below). Both close methods
  are idempotent
- **`SoapClient.close()`**, **`SoapClient.aclose()`**, and
  context-manager support — propagate transport cleanup. Recommended
  usage in long-running processes that create many short-lived
  clients: `with SoapClient(…) as client: …`

### Changed

- **`HttpTransport` now reuses a long-lived `httpx.Client`** (and
  `httpx.AsyncClient` for the async path) across `send()`, `fetch()`,
  and `send_async()` invocations. The client is lazy-initialized on
  first use and pooled by httpx internally, so consecutive requests
  to the same host reuse TCP/TLS connections. Pre-0.6.1 behavior
  created a fresh `with httpx.Client(...)` per request — measurably
  slower under load. No public API change for callers that do not
  invoke `close()`

### Docs

- **README Known Limitations** extended with four new rows: SOAP 1.2
  recursive `Subcode` support on `SoapFault` (previously undocumented
  feature surfaced); WSDL 2.0 declared unsupported (WSDL 1.1 only);
  WS-Policy / WS-PolicyAttachment declared out of scope;
  WS-ReliableMessaging / WS-Trust / WS-SecureConversation /
  WS-Federation declared out of scope
- **`SECURITY.md`** gains a section on WS-Addressing reply/fault
  routing (A04, A05): EPRs are validated on parse but soapbar does
  not dispatch responses or faults to the addresses they encode —
  everything returns on the HTTP back-channel. The `WSA_ANONYMOUS`
  and `WSA_NONE` constants are referenced for callers layering
  EPR-aware logic on top of `handle_request()`

---

## [0.6.0] — 2026-04-14

### ⚠ Generated WSDL shape change (no on-the-wire SOAP change)

Auto-generated WSDL for `DOCUMENT_LITERAL_WRAPPED` services now emits
WS-I Basic Profile 1.1-conformant message shapes:

- The `<xsd:schema>` block carries `elementFormDefault="qualified"`,
  matching the qualified wire format soapbar's serializer has produced
  since 0.5.3.
- Each operation contributes two global `<xsd:element>` declarations to
  the schema: one named after the operation (input wrapper), one named
  `{OperationName}Response` (output wrapper). Each has an inline
  `<xsd:complexType>` whose `<xsd:sequence>` declares the per-parameter
  child elements.
- Each `<wsdl:message>` for a DLW operation contains exactly one
  `<wsdl:part name="parameters" element="tns:OperationName"/>`,
  referencing the global element rather than a per-parameter
  `type="xsd:…"`. This satisfies WS-I BP 1.1 R2201 (one part per
  document-literal message) and R2204 (part references element=, not
  type=).

**On-the-wire SOAP messages are unchanged from 0.5.x.** Existing
client stubs that are already deployed continue to work without
modification. The change is in the WSDL contract, which means
**consumers that regenerate stubs from soapbar's WSDL will see updated
parameter-binding code** — the new shape is what strict WS-I
validators, Apache CXF, .NET WCF, and WSS4J expect to see in the
first place. Stubs should regenerate cleanly across every major
SOAP stack (zeep / spyne / WCF / CXF / WSS4J), and parameter access
should remain identical at the application level.

RPC/Literal, RPC/Encoded, Document/Encoded, and plain Document/Literal
(non-wrapped) services are unchanged: WS-I permits the per-parameter
`type=` shape for RPC, and encoded styles are already flagged
non-conformant via `BindingStyle.is_wsi_conformant`.

### Added

- **`build_doc_literal_wrapper(name, params)`** in
  `soapbar.core.wsdl.builder` — exposed helper that synthesizes the
  global `<xsd:element>` declaration for a document-literal operation
  wrapper. Useful for callers building custom `WsdlDefinition`
  instances by hand
- **`WsdlDefinition.global_elements: list[Any]`** — new field carrying
  the synthesized wrapper elements. Empty by default; the auto-WSDL
  builder populates it for DLW operations only
- **`tests/audit/test_compliance.py::TestWsiBasicProfile11`** — seven
  conformance tests, one per WS-I BP 1.1 R-number (R2201, R2204,
  R2706, R2710, R2711, R2714, R2716), pinning the new WSDL shape

---

## [0.5.5] — 2026-04-14

### Security

- **Signature-wrapping defense in `verify_envelope` and
  `verify_envelope_bsp`** (WSS 1.0 §4.3; masterprompt §18.5). Two
  layered, pure-Python mitigations:
  - Envelopes containing duplicate `wsu:Id` attribute values are now
    rejected with `XmlSecurityError` before the tree is handed to
    signxml's `XMLVerifier`, preventing the classic pattern where an
    attacker injects a second element carrying the same id as a
    legitimately-signed element.
  - Both verify functions now accept an optional
    `expected_references: int | None = None` keyword that forwards to
    signxml's `expect_references=`. Callers who know the signer's
    reference count (e.g. 2 for Body + Timestamp) should pin it so the
    verifier rejects envelopes where references have been dropped or
    added. Default `None` preserves pre-0.5.5 behavior for existing
    callers
- Docstrings on both verify functions now explicitly state that they
  are not wired into `SoapApplication.handle_request` automatically;
  applications integrating XML Signature verification must invoke them
  directly and SHOULD supply `expected_references` for production use

### Fixed

- **S04 Timestamp `wsu:Id` fallback** — `sign_envelope` and
  `sign_envelope_bsp` constructed `#TS-1` references when a Timestamp
  lacked `wsu:Id` but never actually wrote the attribute back to the
  element. The resulting signature carried a reference URI that
  resolved to nothing. Both sign paths now set the attribute on the
  element when missing, mirroring the Body handling. Fixes an S04
  edge-case that was masked by existing tests supplying pre-existing
  Timestamp ids

---

## [0.5.4] — 2026-04-14

### Added

- **`WSA_ANONYMOUS`** and **`WSA_NONE`** constants in
  `soapbar.core.envelope` — the two well-known addresses defined by
  WS-Addressing 1.0 §2.1. Completes the A04 magic-URI allowlist
  follow-on from 0.5.3: callers routing on `wsa:Address` should now
  test against these constants explicitly, since neither refers to a
  real endpoint (the anonymous URI requests back-channel reply; the
  none URI indicates no reply is expected). Two round-trip tests
  added to `tests/audit/test_security.py::TestEprAddressValidation`

### Fixed

- **Mypy strict compliance** for the 0.5.3 A04 / S04 code paths
  (`src/soapbar/core/envelope.py:80`, `src/soapbar/core/wssecurity.py:350`).
  Runtime behavior unchanged — only type-narrowing adjustments

---

## [0.5.3] — 2026-04-14

### Added

- **`SECURITY.md`** — deployer-facing threat model documenting
  certificate-trust limitations (no CRL/OCSP/path-building), the
  spec-mandated SHA-1 in PasswordDigest (WSS 1.0 §3.2.1), and the
  delegation of timeouts / concurrency to the WSGI/ASGI host
- **`TestXmlsecRoundTrip`** in `tests/audit/test_security.py` — four
  new tests that sign envelopes with soapbar and re-verify them via
  `python-xmlsec` (libxmlsec1, the same C library used by Apache
  Santuario / WSS4J / CXF / .NET XmlDsig). Tampered-body negative test
  proves the verifier is not vacuously passing
- **`crypto-interop`** dev-dependency group (`xmlsec>=1.3`) — CI
  installs `libxmlsec1-dev` via apt; local suites without the group
  skip the four xmlsec tests via a `_HAS_XMLSEC` import guard
- **`allow_plaintext_credentials`** parameter on `SoapApplication`
  (default `False`) — opt-out for the new S08 hard-gate
- **`wsdl_access`** (`"public"` / `"authenticated"` / `"disabled"`)
  and **`wsdl_auth_hook`** parameters on `SoapApplication` — optional
  gating for the `?wsdl` endpoint (X06)
- **`SoapApplication.check_wsdl_access(headers)`** public method —
  invoked by WSGI and ASGI adapters before serving the WSDL

### Fixed

- **S04 + S05 (WS-I BSP 1.1 R5404 / R5416 / R5441)** — `sign_envelope`
  and `sign_envelope_bsp` now emit Exclusive XML Canonicalization
  (`http://www.w3.org/2001/10/xml-exc-c14n#`) on `SignedInfo` and
  every `Reference/Transforms/Transform`, and produce discrete
  `ds:Reference` elements for the Body (by `wsu:Id="Body-1"`) and the
  Timestamp (when present). Previously the canonicalization defaulted
  to `signxml`'s Canonical XML 1.1 and the signature was an enveloped
  signature over the root with no discrete references — both patterns
  that WSS4J / Apache CXF / .NET WCF peers reject. Interop with those
  stacks is now unblocked
- **E08 (SOAP 1.2 Part 1 §5.1)** — `SoapEnvelope.from_xml()` now
  rejects SOAP 1.2 envelopes whose `env:Body` contains `env:Fault`
  alongside other sub-elements. The output path already respected the
  constraint; the input-side enforcement was missing
- **S08 (WSS 1.0 §6.2 / WS-I BSP R4202)** — `UsernameToken` with
  `#PasswordText` credentials is now rejected with a `Client` fault
  when arriving at an `http://` service_url. Previously only a
  `UserWarning` was emitted. Override via the new
  `allow_plaintext_credentials=True` flag for dev environments
- **A04 (WS-Addressing 1.0 §2.1)** — `wsa:EndpointReference` parsing
  now requires `wsa:Address` to be present, non-empty, and a valid
  absolute URI; malformed EPRs raise `Client` fault instead of being
  silently accepted with blank addresses

---

## [0.5.2] — 2026-04-13

### Added

- **`TestSpyneInterop`** in `tests/test_interop.py` — soapbar client ↔ spyne
  server interoperability, the symmetric counterpart to `TestZeepInterop`.
  Covers SOAP 1.1, SOAP 1.2, and spyne-generated WSDL parsing by soapbar.
  Skipped automatically when `spyne` is not installed (spyne 2.14.0 is
  incompatible with Python 3.12+, so the tests only execute on 3.10/3.11)
- **`spyne>=2.14`** added to the `dev` dependency group for the new interop tests

### Fixed

- **Document/Literal/Wrapped child element namespace** —
  `DocumentLiteralWrappedSerializer` now emits child elements inside the
  operation wrapper qualified with `sig.input_namespace` /
  `sig.output_namespace` (cascading through `param.namespace`), matching the
  `elementFormDefault="qualified"` convention used by Apache CXF, .NET WCF,
  and spyne. Previously, children were always unqualified, which caused
  schema validation failures when calling Java/.NET/spyne services. The
  matching deserializer accepts both qualified and unqualified forms for
  tolerant parsing

### Changed

- **README conformance framing** — "100% SOAP Protocol Audit" phrasing reworded
  to "internal conformance suite of 135 tests across 10 spec-mapped classes"
  with an explicit note that the suite is self-administered, not a third-party
  audit. Comparison table cells (`—`, `?`) rephrased as `not claimed` and
  `undocumented` to stop implying competitors failed a test they never took
- **PyPI metadata re-published** — the long description shipped with v0.5.1
  ended with a stale "MIT with Attribution" string that contradicted the
  Apache-2.0 license declared in `pyproject.toml`, `LICENSE`, classifiers, and
  the on-disk README; re-uploading 0.5.2 publishes the corrected description

---

## [0.5.1] — 2026-04-12

### Added

- **Apache 2.0 license** — `LICENSE`, `NOTICE`, SPDX headers on all source files,
  `SECURITY.md` private-advisory policy, Dependabot config for pip + github-actions
- **`CODEOWNERS`** — auto-assigns review on PRs to `@hitoshyamamoto`

### Changed

- **Workflow actions pinned to immutable commit SHAs** across `push.yml`, `pr.yml`,
  `release.yml`; github-actions group bumped (checkout v6, upload-artifact v7,
  download-artifact v8)

### Fixed

- **Coverage comment on Dependabot PRs** — switched from `secrets.GH_TOKEN` to
  `secrets.GITHUB_TOKEN` so the step runs for PRs from Dependabot as well

---

## [0.5.0] — 2026-04-12

### Added

- **Python 3.10+ support** — `requires-python` lowered from `>=3.12` to `>=3.10`; CI matrix
  extended to include 3.10 and 3.11; `datetime.UTC` (3.11+) replaced with `timezone.utc`
- **Real-world WSDL integration tests** — `tests/wsdl_samples/` contains `global_weather.wsdl`
  (classic SOAP interop WSDL with SOAP 1.1 and 1.2 bindings) and `hello_world.wsdl`
  (hand-crafted edge-case WSDL covering document/literal, rpc/literal, optional parts,
  multiple port types); 16 new `@pytest.mark.integration` tests in `tests/test_real_wsdls.py`
- **Non-strict WSDL parsing** — `parse_wsdl(..., strict=False)` and
  `parse_wsdl_file(..., strict=False)` silently skip unresolvable `wsdl:import` entries
  (emitting a `warnings.warn`) instead of raising; SSRF guard is always enforced regardless
  of `strict`
- **JSON dual-mode response** — any `@soap_operation` endpoint returns JSON when the HTTP
  client sends `Accept: application/json`; no separate route needed; SOAP faults are also
  serialised as `{"fault": {"code": ..., "message": ..., "detail": ...}}`; Accept header
  matching uses a proper media-type token check so `application/json-patch+json` and similar
  suffixed types do not incorrectly trigger JSON mode (RFC 7231 §5.3.2)

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
- **N05** `wssecurity.py` — `build_security_header()` now emits a `wsu:Timestamp` block with
  `wsu:Created` (now) and `wsu:Expires` (now + 5 min) per WS-Security 1.0 §10; controlled via
  `include_timestamp=True` (default `True`)
- **N06** `wssecurity.py` — sending a `PasswordText` credential now emits a warning
  (`UserWarning`) advising that PasswordText should only be used over TLS; can be suppressed
  with `warnings.filterwarnings`
- **N07** `wssecurity.py` / `application.py` — a nonce replay cache (`_NONCE_CACHE`) rejects
  repeated `wsse:Nonce` values within the `wsu:Timestamp` validity window, preventing replay
  attacks per WS-Security 1.0 §8
- **N09** `application.py` — WS-Addressing `FaultTo` EPR is now respected: when a fault occurs
  and a `wsa:FaultTo` address is present in the request, the fault response is routed to that
  address (non-anonymous EPRs are logged and the response is still returned inline)
- **N11** `envelope.py` — `build_envelope()` now validates the resulting envelope structure
  (exactly one Body, Header before Body if present, no unknown direct children of Envelope)
  and raises `ValueError` on violation before the element is returned
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
- Minimum Python version set to `>=3.12` (subsequently lowered back to `>=3.10` in v0.5.0)

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
