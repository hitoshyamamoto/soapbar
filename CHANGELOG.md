# Changelog

All notable changes to soapbar are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

- **`soapbar.contrib.ana.AnaClient`** — a typed client for ANA ServiceANA, the
  Brazilian National Water Agency's legacy hydrometeorological telemetry service
  (`telemetriaws1.ana.gov.br`, a document/literal-*wrapped* ASP.NET `.asmx`,
  namespace `http://MRCS/`). Covers all 12 operations (telemetric data, the five
  HIDRO catalogues, the 12-filter `HidroInventario`, `HidroSerieHistorica`, the
  telemetric-station registry, and the restricted CotaOnline writes), flattening
  the ADO.NET DataSet (inline schema + Microsoft diffgram) it returns into plain
  dict rows. Ships enums (`TipoDados`, `TipoEstacao`, `OrigemTelemetrica`) and
  documents the service's contract quirks (lowercase `origem`, PascalCase
  CotaOnline elements, plaintext write credentials). Installable via
  `soapbar[ana]`. The service is announced-legacy (superseded by the REST
  `Hidro_Webservice`); treat the client as a bridge for existing SOAP consumers.

---

## [0.13.0] — 2026-07-03

A security and conformance release closing the findings of an internal audit.
Two of the changes alter the wire format / public API (#49, #50) — see the
**Migration** notes — hence the minor-version bump.

### Security

- **Trust anchor required for BSP signature verification
  (GHSA-859w-52fx-hcm6).** `verify_envelope_bsp` previously trusted the X.509
  certificate carried *in the message*, so a valid signature over an
  attacker-minted certificate passed verification (signature forgery /
  authentication bypass). It now **fails closed** unless the caller anchors
  trust with `trusted_certs=[...]` (pin the expected signer) and/or
  `ca_certs=[...]` (accept certs issued by trusted CAs); the anchor is checked
  before the signature is trusted. `verify_cert_trust=False` restores the old
  behaviour explicitly (insecure).
- **XML Encryption is now authenticated (AES-256-GCM) (#55).** `encrypt_body`
  emits AES-256-GCM (XML-Enc 1.1) with a fresh 96-bit IV; the GCM tag lets the
  recipient detect tampering. `decrypt_body` reads the algorithm from
  `xenc:EncryptionMethod`, verifies GCM, and **refuses the legacy,
  unauthenticated AES-256-CBC by default** (malleable / padding-oracle prone) —
  pass `allow_unauthenticated_cbc=True` to accept it for a legacy peer. All
  decrypt failures collapse to one uniform error (no padding oracle), and the
  decrypted content is parsed with the hardened XXE-safe parser.
- **UsernameToken `wsu:Created` freshness enforcement (#56).** The validator now
  rejects a stale `wsu:Created` (`max_created_age`, default = `nonce_ttl`), a
  future-dated one (`max_clock_skew`), and an over-long `wsu:Expires`
  (`max_timestamp_validity`) — closing the replay-after-nonce-TTL window. All
  limits are configurable; set to `None` to opt out.
- **Signature verification requires Body coverage (#57).** `verify_envelope` /
  `verify_envelope_bsp` default `require_signed_body=True`, failing closed
  unless the signature actually covers the SOAP Body (defeats
  reference-stripping). Opt out with `require_signed_body=False`.
- **Ingress size limit enforced before gzip/MTOM decoding (#47).** `max_body_size`
  is now applied ahead of the amplifying stages: bounded gzip decompression
  (rejects a decompression bomb), bounded MTOM/XOP resolution (rejects XOP
  amplification), and a running cap on ASGI streamed bodies. Refuses over-limit
  bodies with the standard fault and bounded memory.
- **WSDL local-file imports blocked from untrusted sources (SSRF) (#48).** The
  import guard now gates `file://` and bare filesystem paths behind a new
  `allow_local_imports` flag (default `False`), so a hostile
  `<import location="file:///etc/passwd">` in an in-memory/remote WSDL cannot
  read local files. `parse_wsdl_file` enables local imports for trusted on-disk
  documents.

### Changed

- **Parsed types are per-parse scoped, not process-global (#49).** Each
  `parse_wsdl` / `parse_wsdl_file` call now registers the complexTypes it parses
  into a *scoped* registry seeded with the built-in XSD types (exposed as
  `WsdlDefinition.type_registry`), instead of the shared module-global `xsd`
  registry. Two documents that define a same-named type no longer clobber each
  other, lazy field references resolve against their own document, and parsing
  is safe under concurrency. **Migration:** the global `xsd` registry still
  resolves the 27 built-in types (`xsd.resolve("int")` etc.), but a
  *user-defined* type is no longer discoverable there after parsing —
  `xsd.resolve("MyParsedType")` returns None; read it from
  `defn.complex_types` / `defn.type_registry` instead. Hand-built
  `ComplexXsdType`s are unaffected (they default to the built-in registry).

- **complexType children now honour `elementFormDefault` (#50).** A
  `ComplexXsdType`/`ArrayXsdType`/`ChoiceXsdType` parsed from a schema with
  `elementFormDefault="qualified"` now emits its *local child* elements in the
  schema's target namespace (`<ns:age>` instead of `<age>`), matching what a
  conformant peer (zeep/.NET/Java) sends and expects. The generated WSDL's
  `elementFormDefault` is emitted to match what the serializer produces, so the
  published schema no longer disagrees with the wire. Deserialization is now
  **namespace-tolerant** (children matched by local name), so soapbar reads both
  qualified and unqualified input regardless of the declared form.

  **Migration:** hand-built `ComplexXsdType`s default to *unqualified* (the XSD
  default and soapbar's prior wire form), so existing code is unchanged; pass
  `qualified=True, target_namespace=...` to emit qualified children. This is a
  wire-format change for parsed-qualified types and for the generated schema's
  declared form — a soapbar peer older than this release, reading a qualified
  message from a newer one, will not find the children by their old unqualified
  names.

- **SOAP 1.2 sender faults return HTTP 400 (#54).** A SOAP 1.2 fault whose Code
  Value is `env:Sender` is now reported with HTTP **400** (per SOAP 1.2 Part 2
  §7.4), not 500. `env:Receiver` and SOAP 1.1 faults are unchanged (500).

### Fixed

- **`maxOccurs>1` elements no longer double-wrapped (#51).** A repeated element
  in a sequence serializes as flat sibling elements
  (`<address>a</address><address>b</address>`) instead of an extra nesting
  level; `ArrayXsdType` gains an `inline` flag distinguishing a repeated element
  from a genuine (wrapper) array type.
- **Spec-conformant `xsd:dateTime` and `xsd:decimal` lexical forms (#52).** A
  Python `datetime` serializes with the ISO-8601 `T` separator (not a space),
  and `xsd:decimal` emits canonical fixed-point (no exponent notation).
- **`xsi:nil` honoured; empty XML no longer conflated with `None` (#53).**
  Optional/`None` scalars are omitted (or emit `xsi:nil` when required) instead
  of an empty element; inbound `xsi:nil="true"` and empty numeric/date elements
  deserialize to `None` instead of crashing on `int("")`.

---

## [0.12.1] — 2026-06-03

### Documentation

- README refreshed for the 0.7.0–0.12.0 integration work: the `soapbar[vies]` /
  `[witsml]` / `[nfe]` install extras, the Features list (mutual TLS +
  `load_pkcs12`, session cookies, Id-targeted signing, document/literal *bare* +
  `xsd:any`, the `soapbar.contrib.*` clients), and the Public API table.
- The VIES / WITSML / NF-e examples now cross-reference their ready-made
  `soapbar.contrib.*` clients. No code changes — docs-only, so the PyPI project
  description reflects the current state.

---

## [0.12.0] — 2026-06-03

### Added

- **`NfeStatusResult` exposes the nested authorization protocol.** New
  `prot_c_stat` / `prot_x_motivo` / `n_prot` fields and an `authorized` shortcut
  (`prot_c_stat == 100`) surface `protNFe/infProt` directly, so
  `consultar_protocolo` callers get the document's authorization status without
  parsing `.raw`.

### Changed

- The NF-e `live` test is hardened: it refuses a non-homologação endpoint
  (skips on a `producao` URL or one lacking `homologacao`), stays pinned to
  `tpAmb=2`, and reads the PFX password inline so it cannot surface in a
  traceback — a real certificate can never drive a produção transaction by
  accident.

---

## [0.11.1] — 2026-06-03

### Fixed

- **`NfeClient` now reads the SEFAZ response.** The response parameter was
  registered as `nfeDadosMsg` (the *request* element), but SEFAZ replies inside
  `nfeResultMsg` — so `status_servico`/`consultar_protocolo` extracted nothing
  and raised `XMLSyntaxError: Document is empty` against every real endpoint.
  Fixed to `nfeResultMsg`; the offline stub is now calibrated to the real
  response element (it would have caught this).

### Added

- **`NfeClient(ca_bundle=…)`** — pass an ICP-Brasil CA chain for server
  verification, since the SEFAZ roots may be absent from the default trust
  store (avoids a TLS failure without hand-building a transport).

### Changed

- `NfeClient.consultar_protocolo` documents that `.c_stat` is the
  `retConsSitNFe` *query* status; the document's authorization status is nested
  in `protNFe/infProt` (read it via `.raw`).

---

## [0.11.0] — 2026-06-03

### Added

- **`soapbar.contrib.nfe.NfeClient`** — a mutual-TLS client for the SEFAZ NF-e
  (Brazilian e-invoice) layout-4.00 web services. Builds the ICP-Brasil mTLS
  transport from a PKCS#12 (`load_pkcs12`), sends the SOAP 1.2 document/literal
  *bare* `nfeDadosMsg` envelope, and parses `cStat`/`xMotivo`. Implements
  `status_servico` (the `cStat == 107` health check), `consultar_protocolo`,
  and `sign()` — an enveloped `<infNFe>` signature with the SEFAZ-mandated
  algorithm set (RSA-SHA1 / SHA-1 / inclusive C14N / end-entity-only KeyInfo).
  It owns the protocol, not the full layout-4 data model. Installable via
  `soapbar[nfe]`.

---

## [0.10.0] — 2026-06-03

### Added

- **Document/literal *bare* + `xsd:any` passthrough.** When a WSDL operation's
  single body part references a global element whose content model is an
  `xsd:any` wildcard, soapbar now sends that element *as* the body (rather than
  re-wrapping it under the operation name) and passes the caller's XML through
  verbatim — and returns the response body's inner XML as a string. This is what
  document/literal bare services such as SEFAZ NF-e (`nfeDadosMsg` /
  `nfeResultMsg`) require: `client.call("nfeStatusServicoNF", nfeDadosMsg="<consStatServ…/>")`
  now reaches the wire correctly instead of dropping the payload. Adds the
  `AnyXmlType` passthrough type.

### Fixed

- **RPC response accessors are matched namespace-agnostically.** The RPC/encoded
  and RPC/literal deserializers matched accessor elements by exact (unqualified)
  name, so a server that qualifies them — by putting a default `xmlns` on the
  response wrapper — yielded no extracted values. For WITSML this surfaced as a
  misleading `WitsmlError 0: no Result code` that masked the server's real
  return code (e.g. `-425`). Matching now ignores the accessor namespace, so
  both the canonical (unqualified) and qualified forms parse.
- **`sign_element_by_id` places the signature beside the signed element.**
  The enveloped `ds:Signature` is now inserted as a sibling of the element it
  covers (a child of that element's parent) rather than at the document root.
  For a single `<NFe>` this is unchanged; inside an `<enviNFe>` batch the
  signature now lands inside the matching `<NFe>` (next to `<infNFe>`) as SEFAZ
  requires, instead of under `<enviNFe>`. The reference and digest are
  unaffected, so signatures remain valid.

---

## [0.9.0] — 2026-06-03

### Added

- **`ViesClient.check_vat_approx(...)`** — the approximate-match VIES operation.
  Returns a `ViesApproxResult` with the `request_identifier` (proof-of-
  consultation token kept for audit) and per-field `MatchCode`s for the trader
  details supplied. Optional `trader_*` / `requester_*` arguments are sent only
  as given.
- **`SoapClient.from_file(transport=…, endpoint=…)`.** The WSDL-from-disk
  constructor now accepts a custom transport (timeouts, mTLS, or a stub in
  tests) and an endpoint override (e.g. force HTTPS when the WSDL lists a legacy
  HTTP URL). `soapbar.contrib.vies.ViesClient` uses these instead of reaching
  into private attributes.

### Fixed

- **WSDL-driven parameters honour `minOccurs="0"`.** Elements declared optional
  in the schema are now registered as optional `OperationParameter`s instead of
  required, so calls that legitimately omit them (and responses that omit
  optional fields) no longer raise "Missing required parameter". This is what
  lets `checkVatApprox` be called with only the trader details you have.

---

## [0.8.1] — 2026-06-03

### Fixed

- **Document/literal request wrapper is now namespace-qualified correctly.**
  When a WSDL declares its message elements in a schema namespace different from
  the WSDL `targetNamespace` (the common real-world case — e.g. EU VIES uses
  `…:checkVat:types` while the WSDL targets `…:checkVat`), the parser now
  resolves each part's `element` to that schema namespace
  (`WsdlPart.element_ns`) and the WSDL-driven client qualifies the request
  wrapper and its children with it. Previously `input_namespace`/
  `output_namespace` came back `None` and soapbar emitted an unqualified
  wrapper, which strict servers — including the live EU VIES service — reject
  ("Expected `{…:checkVat:types}`…"). This makes
  `soapbar.contrib.vies.ViesClient` correct against the real endpoint, and fixes
  WSDL-driven document/literal clients generally.

---

## [0.8.0] — 2026-06-03

### Added

- **`soapbar.contrib.witsml.WitsmlClient`** — a typed client for the WITSML
  1.4.1.1 STORE API (oil & gas). Registers the STORE operations over soapbar's
  RPC binding (the WSDL has no `<types>`; domain XML rides as strings), adds an
  `options_in()` builder for `OptionsIn`, and maps the return code — positive is
  success, negative raises `WitsmlError` (text resolved via `WMLS_GetBaseMsg`).
  Methods: `get_cap`, `get_from_store`, `add_to_store`, `update_in_store`,
  `delete_from_store`, `get_version`, `get_base_message`. WS-Security
  UsernameToken auth; installable via `soapbar[witsml]`.
- **`soapbar.contrib.vies.ViesClient`** — a typed client for the EU VIES VAT
  validation service. `check_vat(country_code, vat_number)` returns a
  `ViesResult` (`valid`, `name`, `address`, `request_date`); input is validated
  against the EC patterns and VIES faults map to typed exceptions
  (`ViesInputError`, `ViesRateLimitError`, `ViesUnavailableError`). The service
  WSDL is bundled, so construction needs no network. Installable via
  `soapbar[vies]`. This is the first of the optional `soapbar.contrib.*`
  integrations — typed convenience clients built on the core API.

### Fixed

- **`xsd:date` now accepts an optional timezone** (e.g. `2026-06-02+02:00`, as
  returned by EU VIES), matching the XSD spec; the lexical value is preserved.
  Previously `date.fromisoformat` rejected the timezone suffix.

---

## [0.7.0] — 2026-06-01

### Added

- **Real-world service examples.** Four new examples point soapbar at actual
  government/industry SOAP services: `examples/17_vies/` (EU VIES VAT
  validation — runs live), `examples/18_witsml/` (WITSML 1.4.1.1 STORE API over
  the RPC binding with manually-registered operations), `examples/19_nfe/`
  (SEFAZ NF-e — mutual TLS + `<infNFe>` `Id`-signing) and `examples/20_mef/`
  (IRS MeF A2A — mutual TLS + session cookies). VIES/WITSML run against live
  endpoints; NF-e/MeF are faithful references whose `main()` prints guidance
  without network access. A smoke test imports all four (guarding against
  public-API drift) and runs the NF-e/MeF references.

- **`sign_element_by_id()` — sign an internal element by its `Id`.** Produces an
  enveloped `ds:Signature` whose single `ds:Reference` targets `#<id>` (the
  standard XML-DSIG pattern for signing an inner element, not the whole
  envelope). Algorithms are configurable: defaults are RSA-SHA256 / SHA-256 /
  Exclusive C14N, and the SEFAZ NF-e mandate is supported via
  `signature_method="rsa-sha1"`, `digest_method="sha1"`, `c14n="inclusive"`
  (the `REC-xml-c14n-20010315` algorithm), with `end_cert_only=True` keeping
  only the end-entity certificate in `KeyInfo`. Exported as
  `soapbar.sign_element_by_id`; requires `signxml` (`soapbar[security]`).
- **Session cookie persistence in `HttpTransport`.** The pooled httpx client
  now carries cookies across calls by default, so a `Set-Cookie` from one SOAP
  call (e.g. a login returning `JSESSIONID`) is sent on the next — the basis
  for stateful services such as IRS MeF. The live jar is exposed as
  `transport.cookies` for reading a session cookie after a call or injecting
  one before; pass `HttpTransport(persist_cookies=False)` for stateless
  behaviour (the jar is cleared after every call). Sync and async.
- **Mutual TLS (client certificates) in `HttpTransport`.** New
  `HttpTransport(client_cert=..., ca_bundle=...)` parameters present a client
  certificate on the TLS handshake and verify the server against a custom CA
  bundle — needed for private/government PKIs (e.g. ICP-Brasil for SEFAZ NF-e,
  IRS MeF Strong Authentication, enterprise WITSML). `client_cert` accepts a
  combined-PEM path, a `(certfile, keyfile[, password])` tuple, or in-memory
  `(cert_pem, key_pem)` bytes; the latter is loaded through an
  `ssl.SSLContext` so the key never lands in a persistent file. Both sync and
  async clients are covered. Mutual TLS requires httpx (`soapbar[client]`).
- **`load_pkcs12(path, password) -> (cert_pem, key_pem)`** helper (exported as
  `soapbar.load_pkcs12`) that converts a PKCS#12 (`.pfx`/`.p12`) bundle — such
  as an ICP-Brasil A1 certificate — into in-memory PEM bytes, returning the
  full certificate chain and the unencrypted PKCS#8 private key. The key is
  never written to disk or logged. Requires `cryptography` (`soapbar[security]`).

---

## [0.6.4] — 2026-04-15

### Changed

- **Repositioned as a SOAP library, not a framework.** The PyPI
  `description` and the README tagline both previously read "A SOAP
  framework for Python". Corrected to "A SOAP library for Python".
  soapbar exposes a decorator-based server API (`SoapService` +
  `@soap_operation`) that mounts inside a host ASGI/WSGI framework; it
  does not own routing, configuration, lifecycle, DI, a CLI, or plugin
  contracts, so "library" is the honest positioning. The GitHub
  repository About blurb was updated in the same pass via `gh repo
  edit`. No API or behaviour change.

### Fixed

- **`examples/10_complex_types/` now round-trips correctly.** Two
  defects prevented the complex-types example from working end-to-end:
  - `client.py` used `SoapClient(wsdl_url=...)`, but the WSDL-driven
    auto-registration path drops the `ComplexXsdType` binding for the
    `User` type — the registered signature falls back to strings and
    the complex fields do not survive the round-trip. Switched to
    `SoapClient.manual(...)` + `register_operation(...)` with an
    explicit `OperationSignature` that carries the `User`
    `ComplexXsdType` on both input and output. A comment in the
    example flags the limitation so readers do not mistake this for
    the recommended client pattern.
  - `server.py` returned the User fields at the top level of the
    result dict. `server/application.py` uses the dict verbatim when
    the handler returns a dict, so the response must be keyed by the
    output-param name (`"user"`). Wrapped the fields accordingly and
    added a comment explaining the contract.
  No library code changes.

### Chore

- `uv.lock` synced from 0.6.2 to 0.6.3 (local lockfile had not been
  regenerated after the previous release).

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
