# Security Assurance Case

This document argues why soapbar's security requirements are met. It states the
threat model, draws the trust boundaries, shows that secure design principles
were applied, and shows how common implementation weaknesses are countered.

It is written for someone evaluating soapbar for production use who needs to
reach a judgement without reading the source. It complements — and does not
replace — [Security](security.md), which documents the controls themselves, and
[`SECURITY.md`](https://github.com/hitoshyamamoto/soapbar/blob/main/SECURITY.md),
which records the trust model and known limitations.

!!! note "Self-assessed"
    This is a self-administered assurance case by the project maintainer. It has
    not been reviewed by an independent third party.

## What is being protected

soapbar is a library, not a service. The assets at risk belong to the
application that embeds it:

| Asset | Why it matters |
|---|---|
| **Availability of the host process** | A SOAP server built on soapbar parses attacker-supplied XML. Unbounded parsing costs turn into denial of service for the whole process |
| **Confidentiality of the host's internal network and filesystem** | XML and WSDL parsing are classic vehicles for XXE and SSRF, which turn a parser into a request forwarder or a file reader |
| **Integrity and authenticity of SOAP messages** | WS-Security signatures and encryption are the basis on which a peer decides a message is genuine. A forged signature that verifies is an authentication bypass |
| **Credentials and private keys** | UsernameToken passwords, TLS client certificates, and XML-DSIG signing keys pass through the library |
| **Confidentiality of the host's internals** | Stack traces and exception text leaking into SOAP faults disclose paths, versions, and logic to an attacker |

## Adversaries

| Adversary | Position | Capability assumed |
|---|---|---|
| **Unauthenticated remote client** | Can reach the SOAP endpoint | Sends arbitrary bytes as a SOAP request: malformed XML, entity bombs, deeply nested or enormous documents, forged security headers |
| **Malicious or compromised peer service** | The remote endpoint a soapbar *client* talks to | Returns hostile responses, hostile WSDL, redirects, oversized or malformed payloads |
| **Author of an untrusted WSDL** | Supplies a WSDL consumed via `parse_wsdl` | Crafts `wsdl:import` / `xsd:import` locations pointing at internal hosts or local files |
| **Network attacker** | On the path between client and service | Attempts interception or modification of traffic; downgrade of transport security |

Explicitly **not** in the threat model: an attacker who already executes code in
the host process, or a malicious deployer. A library cannot defend against
either, and pretending otherwise would weaken the parts of this document that
are real.

## Trust boundaries

soapbar sits between untrusted input and the application's own code. Three
boundaries matter.

```
        ── UNTRUSTED ──────────────────┊──── TRUSTED ─────────────────────
                                       ┊
  Remote peer ──HTTP──▶ ASGI/WSGI host ┊
                                       ┊
   ①  request bytes ──▶ size limit ──▶ depth check ──▶ hardened XML parser
                                       ┊                        │
                                       ┊                        ▼
   ②  security header ──▶ WS-Security verification (fail-closed)
                                       ┊                        │
                                       ┊                        ▼
                                       ┊              deserialized values
                                       ┊                        │
                                       ┊                        ▼
                                       ┊              your service handler
                                       ┊
   ③  WSDL document ──▶ import policy (no fetch by default) ──▶ definition
                                       ┊
        ── DEPLOYER'S RESPONSIBILITY ──┊── TLS termination, timeouts,
                                       ┊   concurrency, certificate chains
```

**Boundary ① — the wire.** Everything arriving from the network is untrusted
until it has passed the size limit, the nesting-depth check, and the hardened
parser. These run *before* a document tree is built, so the cost of rejecting a
hostile document is bounded.

**Boundary ② — cryptographic verification.** A signature or token is untrusted
until verified against an anchor the *caller* supplied. Material carried inside
the message never authenticates itself.

**Boundary ③ — document references.** A WSDL may reference other documents. By
default soapbar resolves none of them from the network or the filesystem;
crossing this boundary requires the caller to opt in explicitly.

What lies outside soapbar's boundary, and is therefore the deployer's
responsibility, is stated in `SECURITY.md`: TLS termination, per-request
read/write timeouts, connection concurrency limits, and X.509 chain validation
against a trust store (soapbar checks the validity window, not revocation or
path building).

## Threats and how they are countered

| Threat | Control | Where |
|---|---|---|
| XXE / external entity disclosure | Parser built with `resolve_entities=False`, `no_network=True`, `load_dtd=False`; entity references are dropped, never expanded | `core/xml.py` |
| Billion-laughs / entity expansion DoS | Same parser flags plus `huge_tree=False` | `core/xml.py` |
| Stack exhaustion via nesting | `check_xml_depth` rejects beyond 100 levels using `iterparse`, before a tree is built | `core/xml.py` |
| Memory exhaustion via large bodies | `max_body_size` (10 MB default) enforced before parsing, and before gzip/MTOM expansion | `server/application.py` |
| SSRF via `wsdl:import` / `xsd:import` | Imports are not fetched unless `allow_remote_imports=True`; local-file imports require `allow_local_imports=True`. Import depth capped | `core/wsdl/parser.py` |
| SSRF via arbitrary URL schemes | Transport restricts request URLs to `http`/`https` | `client/transport.py` |
| Signature forgery / authentication bypass | `verify_envelope_bsp` fails closed unless the caller anchors trust (`trusted_certs` and/or `ca_certs`); the certificate carried in the message does not authenticate itself | `core/wssecurity.py` |
| Signature wrapping (signature does not cover the Body) | Verification requires the signature to cover the Body element | `core/wssecurity.py` |
| Ciphertext tampering | Body encryption is AES-256-GCM (authenticated); legacy unauthenticated AES-256-CBC is rejected on decrypt unless explicitly opted in | `core/wssecurity.py` |
| Replay of UsernameToken digests | `wsu:Created` freshness window and nonce tracking | `core/wssecurity.py` |
| Credential exposure in transit | Construction warns when `service_url` is plain HTTP, and again when a security validator is configured over HTTP; PasswordText over plain HTTP is refused unless explicitly allowed | `server/application.py` |
| Transport interception / downgrade | TLS certificate verification is on by default (`verify_ssl=True`); custom CA bundles and mutual TLS are supported | `client/transport.py` |
| Information disclosure through faults | Unhandled exceptions produce a generic message; no stack traces or exception text reach the client | `server/application.py` |
| Weak cryptographic defaults | Signing defaults to RSA-SHA256 / SHA-256 / exclusive C14N; encryption to AES-256-GCM with RSA-OAEP. Legacy algorithms are opt-in per call | `core/wssecurity.py` |
| Supply-chain tampering with releases | Releases are signed with Sigstore keyless provenance and ship a CycloneDX SBOM; see [Verifying a release](security.md#verifying-a-release) | `.github/workflows/release.yml` |

One deliberate exception is documented rather than hidden: the WS-Security
`PasswordDigest` token type uses SHA-1, because the OASIS UsernameToken Profile
defines it that way. It is an interoperability requirement, the input is salted
with a random nonce and a timestamp, and every other security-relevant default
is SHA-256. The same applies to the RSA-SHA1 signing profile, which exists only
because SEFAZ NF-e mandates it and must be requested explicitly.

## Secure design principles applied

**Fail closed.** Where a security decision is ambiguous, soapbar refuses rather
than proceeds. `verify_envelope_bsp` refuses to verify without a caller-supplied
trust anchor — this was a real vulnerability (GHSA-859w-52fx-hcm6), fixed by
inverting the default rather than by patching around the symptom. Decryption
refuses unauthenticated ciphertext. WSDL imports refuse to resolve.

**Secure by default; insecurity is explicit and named.** Every relaxation is an
opt-in keyword argument whose name states what it does:
`allow_remote_imports`, `allow_local_imports`, `allow_unauthenticated_cbc`,
`verify_cert_trust=False`, `verify_ssl=False`. None can be set by accident:
optional arguments across the public API are keyword-only, so a security switch
can never be bound positionally.

**Least authority.** The parser is constructed without network access, without
DTD loading, and without entity resolution — capabilities it does not need are
not available to it, rather than being available and guarded.

**Complete mediation, early.** Size and depth are checked before parsing, not
after; the expensive operation is never reached by input that should be
rejected.

**Economy of mechanism.** No cryptography is implemented in soapbar. Signing,
encryption, and TLS are delegated to `cryptography`, `signxml`, and the standard
library's `ssl`. The library's job is to use them correctly, not to reimplement
them.

**Explicit boundaries.** What soapbar does not do — revocation checking, chain
building, timeouts, concurrency limits, outbound EPR dispatch — is written down
in `SECURITY.md` and in [Known limitations](limitations.md), so a deployer can
see the gap rather than assume it is covered.

## Common implementation weaknesses countered

The controls above are asserted continuously, not assumed:

- **Static analysis.** CodeQL with the `security-extended` query pack runs on
  every pull request and push to `main`, plus weekly. `ruff` with the
  flake8-bandit rule set and `mypy --strict` run in the same CI.
- **Coverage-guided fuzzing.** An Atheris/libFuzzer harness feeds arbitrary
  bytes into every parser that accepts untrusted input — `parse_xml`,
  `check_xml_depth`, `SoapEnvelope.from_xml`, `parse_wsdl` — and treats any
  exception outside the documented contract (`LxmlError`, `ValueError`,
  `SoapbarError`) as a crash. It runs weekly.
- **Property-based testing.** Hypothesis properties assert round-trip and
  robustness invariants for the XSD type system, envelope serialization, and the
  parsers, as part of the normal test suite.
- **Conformance suite.** 116 spec-mapped tests covering SOAP 1.1/1.2, WSDL 1.1
  and WS-I Basic Profile 1.1, including the BSP X.509 token profile.
- **Regression tests for security fixes.** Every security fix to date shipped
  with tests in the same commit, including the trust-anchor fix, the
  authenticated-encryption change, the signature-coverage check, the timestamp
  freshness window, and the local-file import restriction.
- **Coverage.** 95.7% statement and 88.6% branch coverage, with a CI gate that
  fails below 93% combined.

## Residual risk

Stated plainly, because an assurance case that claims no residual risk is not
credible:

- **Bus factor of 1.** One maintainer, no co-maintainer with independent access.
  See [Governance](https://github.com/hitoshyamamoto/soapbar/blob/main/GOVERNANCE.md).
- **No independent security audit.** Every review to date has been
  self-administered.
- **Limited production exposure.** soapbar has no known production deployment,
  so its controls have not been stressed by real adversarial traffic.
- **Certificate trust is delegated.** soapbar validates certificate validity
  windows, not revocation or chain path. A deployer who does not pre-validate
  chains has weaker authentication than this document implies.
- **Memory safety of dependencies.** Python is memory-safe; `lxml`/`libxml2` is
  not. soapbar's hardening reduces the exposed surface but does not eliminate a
  parser vulnerability in the C library beneath it.
