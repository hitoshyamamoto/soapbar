# Roadmap

What soapbar intends to do — and deliberately not do — over the next twelve
months (through July 2027). This is a statement of intent from a
single-maintainer project, not a delivery commitment with dates; see
[GOVERNANCE.md](GOVERNANCE.md) for how that affects reliability.

Scope decisions already settled are recorded in
[docs/limitations.md](docs/limitations.md); the API contract that constrains all
of this is [STABILITY.md](STABILITY.md).

## Where the project is

soapbar is **Beta** (`0.15.x`). The public surface is frozen by a CI-enforced
snapshot test, the security posture is in place (hardened parser, WS-Security,
CodeQL, weekly fuzzing, signed releases with SBOM), and the library is
interoperable with zeep and spyne.

What it does not have is adoption: there is no known production deployment. That
shapes the priorities below more than any technical consideration.

## Near term

**Stability over surface area.** The public API is frozen deliberately, and the
current goal is to keep it that way while real usage accumulates. New public
names are added only when a concrete use case cannot be served by the existing
surface.

- **Correctness and interoperability fixes** against real services, driven by
  reports from actual users. This is the highest-priority category: an
  interoperability bug against a live government or industry endpoint outranks
  any new feature.
- **Keeping contrib clients working.** `soapbar.contrib.*` wraps
  externally-owned services (EU VIES, SEFAZ NF-e, WITSML, ANA) that change
  without notice. Maintaining these against upstream changes is ongoing work,
  and the reason contrib sits in a lower stability tier.
- **Python version tracking.** Support for CPython 3.15 will be added once the
  dependency chain — principally lxml — publishes wheels for it. Until then a
  3.15 CI lane would compile from source and be unreliable rather than
  informative.
- **Documentation for evaluators.** The threat model and assurance case
  ([docs/assurance-case.md](docs/assurance-case.md)) exist so that a security
  team can assess soapbar without reading the source. Expanding these as the
  design evolves is treated as part of the work, not an afterthought.

## The road to 1.0.0

`1.0.0` is **reserved**, and reaching it is not a matter of ticking off
features. The stabilization work it depends on — a common exception base, a
frozen export set, keyword-only optional arguments, immutable value objects — is
already done and shipped in 0.15.0.

What remains is not code: **1.0.0 will be cut when soapbar has demonstrated
institutional adoption**, meaning at least one organization running it in
production whose use case has exercised the API enough to justify committing to
it permanently. Declaring 1.0 without that would be promising a contract the
project has no evidence it should be locked into.

Until then the project stays on `0.y.z`, where minor releases may carry breaking
changes, each documented with its migration in the CHANGELOG.

## Explicitly not planned

These are settled decisions, not a backlog. They will not be implemented in this
period, and issues requesting them will be closed with a pointer here.

| Not planned | Reasoning |
|---|---|
| **WSDL 2.0** | Adoption is low outside JAX-WS/Metro; WSDL 1.1 remains the de facto standard and interoperates cleanly with zeep, spyne, WCF, CXF and WSS4J |
| **WS-Policy / WS-PolicyAttachment** | Declarative policy belongs upstream of the library; deployers should run a policy processor or agree the policy out-of-band |
| **WS-ReliableMessaging, WS-Trust, WS-SecureConversation, WS-Federation** | Token issuance, session continuity and federation are substantially larger specs than the message-level security soapbar targets, and would not be maintainable at this bus factor |
| **SOAP intermediary relaying** | The SOAP 1.2 `relay` attribute is parsed and exposed, but actually forwarding messages as an intermediary is out of scope |
| **Outbound dispatch to `wsa:ReplyTo` / `wsa:FaultTo`** | Endpoint References are parsed and validated, never dispatched to. Making the server originate outbound HTTP is a significant SSRF surface and is a deliberate non-goal — see [SECURITY.md](SECURITY.md) |
| **Certificate revocation checking (CRL/OCSP) and path building** | Deployers pre-validate chains out-of-band against their own trust store; embedding a PKI stack would duplicate what `cryptography` and the platform already provide. A `certificate_validator` hook may be exposed instead |
| **An async server adapter beyond ASGI** | `AsgiSoapApp` and `WsgiSoapApp` cover the deployment targets that exist; framework-specific adapters are better maintained outside the library |

## How this document changes

The roadmap is revised when scope decisions change, and is expected to be
reviewed at least once per release cycle. Proposals to change it belong in an
issue, per [GOVERNANCE.md](GOVERNANCE.md).
