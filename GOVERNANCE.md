# Governance

This document describes how soapbar is governed: who decides what, which roles
exist, and what happens to the project if the maintainer becomes unavailable.
For the API contract see [STABILITY.md](STABILITY.md); for the security trust
model see [SECURITY.md](SECURITY.md).

## Model

soapbar is a **single-maintainer project**. [@hitoshyamamoto](https://github.com/hitoshyamamoto)
is the author and sole maintainer, and holds final decision authority over
scope, design, and releases.

This is stated plainly rather than dressed up as a committee: the project has
one human contributor, and pretending otherwise would misrepresent its bus
factor to anyone evaluating it for production use.

Decisions are made in the open:

- **Feature and scope proposals** are discussed in [GitHub issues](https://github.com/hitoshyamamoto/soapbar/issues)
  before implementation. Anything that changes the public surface must reference
  [STABILITY.md](STABILITY.md) and update the frozen API snapshot deliberately.
- **Changes land only through pull requests.** A branch ruleset on `main`
  requires a PR and eight passing status checks, with no bypass actors — the
  maintainer included. Direct pushes to `main` are rejected.
- **Disagreements** are resolved in the issue or PR thread. If no consensus is
  reached, the maintainer decides and records the reasoning in the thread, so
  the rationale stays discoverable.
- **Out-of-scope requests** are closed with a pointer to
  [docs/limitations.md](docs/limitations.md) or [ROADMAP.md](ROADMAP.md), which
  document what soapbar deliberately does not do.

## Roles and responsibilities

Today every role below is held by the maintainer. They are listed separately
because they carry different duties, and because separating them is the first
step if a co-maintainer joins.

| Role | Responsibilities | Currently held by |
|---|---|---|
| **Maintainer** | Final say on scope and design; merges pull requests; owns the roadmap | @hitoshyamamoto |
| **Reviewer** | Reviews proposed changes for correctness, API impact, and test coverage. Assigned automatically via [`.github/CODEOWNERS`](.github/CODEOWNERS) | @hitoshyamamoto |
| **Security responder** | Receives private vulnerability reports, triages and fixes them, coordinates disclosure and advisories per [.github/SECURITY.md](.github/SECURITY.md) | @hitoshyamamoto |
| **Release manager** | Approves the automated release pull request, which tags, publishes to PyPI, and signs the release. See [CONTRIBUTING.md](CONTRIBUTING.md#releases) | @hitoshyamamoto |
| **Code of Conduct enforcer** | Handles conduct reports per [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | @hitoshyamamoto |

## Becoming a maintainer

There is no closed circle. A contributor who submits several substantial,
well-tested changes and shows sound judgement about the security-sensitive parts
of the codebase (WS-Security, the XML parser, the WSDL import handling) may be
invited to become a co-maintainer, with commit and release rights.

If you are interested, the most useful starting point is an issue describing
what you want to work on, so scope can be agreed before the code is written.

## Continuity

**The project's bus factor is 1.** If the maintainer becomes unavailable, no
one else can currently merge changes or publish releases. That is an accurate
statement of risk, and anyone adopting soapbar for critical work should weigh
it.

What limits the damage:

- **The licence permits an immediate fork.** soapbar is Apache-2.0. Anyone may
  fork the repository, publish it under a different name, and continue
  maintenance without asking permission. Nothing in the project's design,
  tooling, or dependencies requires access to the maintainer's accounts to
  continue development: the full history, the tests, the CI workflows, and the
  release pipeline are all in the repository.
- **The release pipeline is reproducible from the repository.** Releases are cut
  by [`release-please`](https://github.com/googleapis/release-please) and
  published to PyPI via OIDC trusted publishing, both defined in
  `.github/workflows/`. A fork can stand up the same pipeline by configuring its
  own PyPI trusted publisher — there are no private signing keys to inherit.
- **No secret is required to build or verify.** Release artifacts are signed with
  Sigstore keyless signing tied to the workflow identity, not to a personal key,
  so verification does not depend on the maintainer either. See
  [Verifying a release](docs/security.md#verifying-a-release).
- **Account recovery.** The GitHub and PyPI accounts have recovery configured.
  In the event of prolonged unavailability, the appropriate route is to contact
  GitHub Support and PyPI Support about the project's status; both have
  documented processes for abandoned projects, and PyPI publishes a
  [project-takeover policy](https://peps.python.org/pep-0541/) (PEP 541).

What this does **not** provide: continuity of *this* project on *these*
accounts. If the maintainer became unavailable, nobody could merge a pull
request or publish a release to the existing PyPI project within a week. A fork
can continue the software, but under a different name and after a delay.

Two arrangements would close that gap, and neither has been made yet:

1. **A co-maintainer with independent access** — commit and release rights held
   by a second person. This is the preferred answer, and it would also raise the
   project's bus factor above 1.
2. **Credential escrow** — the account recovery material held in escrow
   (a lockbox, a password manager's emergency access, or similar) together with
   a will granting the legal rights needed to continue the project. This is the
   route the OpenSSF Best Practices criteria explicitly recognise for
   single-person projects.

Until one of these exists, this criterion is honestly recorded as unmet in the
project's badge entry rather than argued around. It will be updated here when
that changes.

## Changing this document

Changes to governance follow the same path as any other change: a pull request,
open discussion, and the ruleset's required checks.
