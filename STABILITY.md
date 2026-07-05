# API Stability and Versioning

This document defines what counts as soapbar's **public API**, what stability you
can rely on, and how the project evolves it. For the security trust model see
[`SECURITY.md`](SECURITY.md); for the change history see
[`CHANGELOG.md`](CHANGELOG.md).

The public surface is not just documented here — it is **pinned by a test**
(`tests/test_public_api.py`, run in CI). Every addition, removal,
rename, or signature change to a public symbol must update that snapshot in the
same commit, so no part of the contract changes by accident.

---

## What is public

Two things, and only these two:

1. **The top-level package.** Every name exported from `soapbar` — i.e. every
   name in `soapbar.__all__`. Import them from the top level:

   ```python
   from soapbar import SoapClient, SoapApplication, SoapFault, verify_envelope
   ```

   Some of these names are also reachable through a deeper module path (e.g.
   `soapbar.core.wssecurity.verify_envelope`). The deep path may keep working,
   but **the top-level name is the supported one**; deep paths are not part of
   the contract and may be reorganised.

2. **The contrib clients.** The four optional real-world clients under
   `soapbar.contrib.*`, each restricted to the names in that module's
   `__all__`:

   ```python
   from soapbar.contrib.vies import ViesClient
   from soapbar.contrib.nfe import NfeClient
   from soapbar.contrib.ana import AnaClient
   from soapbar.contrib.witsml import WitsmlClient
   ```

   These are a **separate, lower stability tier** — see below.

## What is not public

Anything else is internal and may change in any release without notice:

- Everything under `soapbar.core.*`, `soapbar.server.*`, and
  `soapbar.client.*` that is **not** re-exported from the top-level `soapbar`
  package.
- Any name beginning with an underscore (`_helper`, `_SoapMethod`'s former
  self, private attributes on public objects).
- Import paths themselves, for symbols that are also exported at the top level.
- The exact text of exception messages, log output, and generated WSDL/XML
  formatting (the *structure* is contractual where documented; the byte-for-byte
  serialization is not).

If you find yourself importing from a deep `soapbar.core...` path that is not in
the top-level `__all__`, treat it as unsupported and open an issue asking for it
to be promoted.

---

## Versioning

soapbar follows [Semantic Versioning](https://semver.org/). While the project is
**pre-1.0** (`0.y.z`), the 0.x convention applies:

| Bump | Example | May break the public API? |
|------|---------|:--------------------------:|
| Patch | `0.14.1 → 0.14.2` | No |
| Minor | `0.14.x → 0.15.0` | Yes — breaking changes land here, and are called out in the CHANGELOG |
| — | (pre-releases) | — |

A `1.0.0` release will mark the point at which the **core** public API is
considered settled: after 1.0, breaking changes to core require a major-version
bump. The stabilization work leading up to it (a common exception base, a frozen
export set, keyword-only optional arguments, immutable value objects) is aimed at
making that contract one worth committing to.

Every breaking change — pre- or post-1.0 — is listed under a **Changed** or
**Removed** heading in the CHANGELOG, with the migration in the entry.

---

## Two tiers: core vs contrib

soapbar has two stability tiers, because they carry different risks.

**Core** — the SOAP toolkit itself (client, server, WSDL, WS-Security, MTOM,
types, faults). soapbar owns this contract end to end and evolves it under the
SemVer rules above.

**Contrib** (`soapbar.contrib.*`) — typed convenience clients for **externally
owned** services: EU VIES, ANA ServiceANA, SEFAZ NF-e, WITSML. These wrap
contracts defined and changed by third parties (government agencies, an industry
consortium) entirely outside soapbar's control. Consequently:

- A contrib client's signature or return shape **may change in a minor release**
  when the upstream service changes, is versioned, or is retired — even if that
  would be a breaking change under the core rules.
- Contrib clients have **uneven real-world verification** (some are validated
  against live endpoints, others structurally only); each module's docstring
  states its status.
- This is not hypothetical: ANA has already announced the discontinuation of
  ServiceANA (superseded by a REST service), so `soapbar.contrib.ana` is
  explicitly a bridge for existing SOAP consumers, not a long-term contract.

If you need a hard stability guarantee, depend on **core** and build your own
thin client, using the contrib module as a reference. Each contrib module is
self-contained and could be vendored into your project unchanged.

---

## Deprecation policy

When a public core symbol needs to be removed or changed incompatibly, we
deprecate before removing:

1. The old form keeps working and emits a `DeprecationWarning` that names the
   replacement.
2. It is listed under a **Deprecated** heading in the CHANGELOG.
3. It is removed no sooner than the **next minor release** (pre-1.0) or the next
   **major release** (post-1.0), whichever the SemVer rules require.

Where a change cannot be made gradual (a security fix that must fail closed, for
instance), we say so explicitly in the CHANGELOG and release notes rather than
pretend a silent migration exists.

---

## Conventions the contract relies on

A few deliberate, load-bearing conventions across the public API:

- **A common exception base.** Everything soapbar raises deliberately derives
  from `SoapbarError`, so `except SoapbarError` catches any library-originated
  failure. `BodyTooLargeError` additionally subclasses `ValueError` for
  backwards compatibility.
- **Optional arguments are keyword-only.** Required "leader" arguments are
  positional-or-keyword; everything optional after them must be passed by
  keyword. This keeps their order out of the frozen contract (so new options can
  be inserted) and prevents security switches from being bound by position.
- **Value objects are immutable.** Parsed/descriptor results (`MtomMessage`,
  `MtomAttachment`, `SoapHeaderBlock`, `WsaEndpointReference`,
  `OperationParameter`) are frozen and hashable; their sequence fields are
  tuples. The two configuration objects assembled incrementally
  (`OperationSignature`, `WsaHeaders`) are intentionally mutable.
- **`SoapClient.call` has an arity-based return shape**: no output → `None`;
  exactly one output parameter → that value unwrapped; two or more → a `dict`
  keyed by parameter name.
