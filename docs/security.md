# Security

soapbar uses a hardened lxml parser:

```python
lxml.etree.XMLParser(
    resolve_entities=False,   # XXE prevention
    no_network=True,          # SSRF prevention
    load_dtd=False,           # DTD injection prevention
    huge_tree=False,          # Billion-Laughs prevention
    remove_comments=True,     # comment injection prevention
    remove_pis=True,
)
```

Entity references (potential XXE payloads) are silently dropped rather than expanded. No network connections are made during parsing. DTDs are not loaded.

Additional hardening:

- **SSRF guard on WSDL imports**: `wsdl:import` / `xsd:import` locations are not fetched by default — remote (`http(s)://`) imports require `parse_wsdl(..., allow_remote_imports=True)` and local-file imports require `allow_local_imports=True`, so a hostile WSDL cannot reach internal hosts or read local files.
- **Message size limit**: `SoapApplication(max_body_size=10*1024*1024)` — requests exceeding 10 MB are rejected with a `Client` fault before XML parsing.
- **XML nesting depth**: requests exceeding 100 levels of nesting are rejected to prevent stack exhaustion.
- **Error scrubbing**: unhandled exceptions produce `"An internal error occurred."` — no stack traces or exception text are returned to clients.
- **HTTPS warning**: `SoapApplication` warns at construction time if `service_url` uses plain HTTP.

---

## Client DEBUG logging and credentials

`soapbar.client.client` and `soapbar.client.transport` emit request and response
envelopes at `DEBUG`. Nothing is logged unless you opt in, and the envelopes are
redacted before they reach a log record:

- `wsse:Security` header blocks are emptied, so a `UsernameToken` password never
  appears.
- Elements whose local name names a secret — `Password`, `Senha`, `Secret` and
  similar, in any namespace — have their text replaced **wherever they appear,
  including the Body**. Not every service carries credentials in the WS-Security
  header: `soapbar.contrib.ana`'s CotaOnline operations authenticate with
  `Login`/`Senha` as plain Body elements.
- Usernames are deliberately **not** redacted. Knowing which account was used is
  most of a debug log's value, and a login is not a credential on its own.
- Bodies that are not parseable XML — an MTOM multipart payload, a proxy's HTML
  error page — are described (`<N bytes, not parseable as XML …>`) rather than
  dumped, and every logged envelope is capped at 8192 characters.

!!! warning "Redaction is best-effort"

    soapbar cannot know the element names of every service it talks to. If your
    service carries a secret in a field this list does not name, that field will
    be logged. Treat `DEBUG` on the client as something you turn on deliberately,
    for a bounded period, against a log sink you control — not as a level to leave
    enabled in production.

---

## Security assurance

These protections are verified continuously, not just designed in:

- **Static analysis** — [CodeQL](https://github.com/hitoshyamamoto/soapbar/blob/main/.github/workflows/codeql.yml) with the `security-extended` query pack, plus ruff's flake8-bandit rules and strict mypy, run on every push and pull request.
- **Fuzzing** — a coverage-guided [Atheris/libFuzzer harness](https://github.com/hitoshyamamoto/soapbar/blob/main/fuzz/fuzz_parsing.py) feeds arbitrary bytes into every parser that accepts untrusted input (`parse_xml`, `check_xml_depth`, `SoapEnvelope.from_xml`, `parse_wsdl`) on a weekly schedule; any exception outside the documented error contract counts as a crash.
- **Property-based tests** — [Hypothesis properties](https://github.com/hitoshyamamoto/soapbar/blob/main/tests/test_properties.py) assert round-trip and robustness invariants for the XSD type system, envelope serialisation, and the parsers, as part of the normal test suite.
- **OpenSSF** — soapbar holds the [OpenSSF Best Practices passing badge](https://www.bestpractices.dev/projects/13849) and is monitored by [Scorecard](https://scorecard.dev/viewer/?uri=github.com/hitoshyamamoto/soapbar).

## Verifying a release

Every release is signed with [Sigstore](https://www.sigstore.dev/) keyless
signing and ships a CycloneDX SBOM. Each [GitHub release](https://github.com/hitoshyamamoto/soapbar/releases)
carries four assets: the wheel, the sdist, `soapbar-<version>.cdx.json` (the
SBOM), and `soapbar-<version>-provenance.sigstore.json` (the signature bundle).

There is **no public key to fetch**. Signing is keyless: the signing identity is
the GitHub Actions workflow itself, and the certificate is issued at build time
via OIDC and recorded in the public Sigstore transparency log. To verify, you
assert which workflow in which repository you expect:

```bash
# Download the artifact and verify it was built by this repo's release workflow
gh release download v0.15.3 --repo hitoshyamamoto/soapbar --pattern '*.whl'

gh attestation verify soapbar-0.15.3-py3-none-any.whl \
    --repo hitoshyamamoto/soapbar \
    --signer-workflow hitoshyamamoto/soapbar/.github/workflows/release.yml
```

A successful run confirms the artifact was produced by that workflow, from this
repository, and has not been modified since. The SBOM is signed by the same
attestation, so it can be verified the same way.

Packages installed from PyPI carry [PEP 740](https://peps.python.org/pep-0740/)
attestations published by the same pipeline; PyPI displays and verifies these
automatically, and they are visible via the `/integrity/` endpoint for each file.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.** Use the private disclosure process in the [security policy](https://github.com/hitoshyamamoto/soapbar/blob/main/.github/SECURITY.md) — a [GitHub private security advisory](https://github.com/hitoshyamamoto/soapbar/security/advisories/new) visible only to you and the maintainer. As a single-maintainer project the targets are acknowledgement within 5 business days and an initial assessment within 14 days, with fix timelines agreed with the reporter by severity.

---

## WS-Security — UsernameToken

soapbar supports WS-Security 1.0 UsernameToken (OASIS 2004), both plain-text and SHA-1 digest.

### Client — attaching credentials

```python
from soapbar import SoapClient
from soapbar.core.wssecurity import UsernameTokenCredential

# Plain-text password
cred = UsernameTokenCredential(username="alice", password="secret")

# SHA-1 PasswordDigest (recommended for non-TLS scenarios)
cred = UsernameTokenCredential(username="alice", password="secret", use_digest=True)

client = SoapClient.manual(
    "https://example.com/soap",
    wss_credential=cred,
)
result = client.call("GetData", id=42)
```

The `wsse:Security` header is injected automatically on every call.

### Server — validating credentials

```python
from soapbar import SoapApplication
from soapbar.core.wssecurity import UsernameTokenValidator, SecurityValidationError


class MyValidator(UsernameTokenValidator):
    _users = {"alice": "secret", "bob": "hunter2"}

    def get_password(self, username: str) -> str | None:
        return self._users.get(username)


app = SoapApplication(
    service_url="https://example.com/soap",
    security_validator=MyValidator(),
)
app.register(MyService())
```

`SecurityValidationError` is converted to a `Client` SOAP fault automatically. Both PasswordText and PasswordDigest token types are verified; Digest requires `wsse:Nonce` and `wsu:Created` to be present.

---

## XML Signature and Encryption

Requires `pip install soapbar[security]` (pulls in `signxml` and `cryptography`).

### XML Digital Signature (XML-DSIG)

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import CertificateBuilder
from soapbar.core.wssecurity import sign_envelope, verify_envelope, XmlSecurityError

# Sign — enveloped RSA-SHA256 XML-DSIG
signed_bytes = sign_envelope(envelope_bytes, private_key, certificate)

# Verify — raises XmlSecurityError on bad signature
try:
    verified_bytes = verify_envelope(signed_bytes, certificate)
except XmlSecurityError as exc:
    print("Signature invalid:", exc)
```

#### Signing an internal element by `Id`

Some services sign an inner element selected by its `Id` (referenced as
`#<id>`) rather than the whole envelope — most notably SEFAZ NF-e, which signs
`<infNFe>`. `sign_element_by_id` does exactly that, with a single
`ds:Reference` and an enveloped signature:

```python
from soapbar.core.wssecurity import sign_element_by_id

# Defaults: RSA-SHA256 / SHA-256 / Exclusive C14N.
signed = sign_element_by_id(nfe_xml, "NFe3106...", private_key, certificate)

# SEFAZ NF-e mandates the legacy algorithm set:
signed = sign_element_by_id(
    nfe_xml,
    "NFe3106...",            # the <infNFe Id="..."> value
    private_key,
    certificate,
    signature_method="rsa-sha1",
    digest_method="sha1",
    c14n="inclusive",        # http://www.w3.org/TR/2001/REC-xml-c14n-20010315
    end_cert_only=True,      # only the end-entity cert in KeyInfo
)
```

### XML Encryption (AES-256-GCM + RSA-OAEP)

```python
from soapbar.core.wssecurity import encrypt_body, decrypt_body, XmlSecurityError

# Encrypt SOAP Body — AES-256-GCM session key wrapped with recipient's RSA public key
encrypted_bytes = encrypt_body(envelope_bytes, recipient_public_key)

# Decrypt — extracts and unwraps the session key, restores Body children
decrypted_bytes = decrypt_body(encrypted_bytes, recipient_private_key)
```

The `xenc:EncryptedData` element is placed as the sole child of `<soap:Body>`. The body is encrypted with **AES-256-GCM** (XML-Enc 1.1, authenticated: the 16-byte GCM tag detects tampering), and the AES-256 session key is wrapped with RSA-OAEP (SHA-256) in an `xenc:EncryptedKey` element inside `xenc:KeyInfo`. Decryption accepts GCM by default; legacy unauthenticated AES-256-CBC ciphertext is rejected unless explicitly opted in via `decrypt_body(..., allow_unauthenticated_cbc=True)`.

### WS-I BSP X.509 Token Profile (S10)

For interoperability with WS-I Basic Security Profile 1.1 compliant clients and servers, use the BSP variant which embeds the certificate as a `wsse:BinarySecurityToken` and references it from `ds:Signature/ds:KeyInfo`:

```python
from soapbar.core.wssecurity import (
    sign_envelope_bsp,
    verify_envelope_bsp,
    build_binary_security_token,
    extract_certificate_from_security,
)

# Sign — adds wsse:BinarySecurityToken + wsse:SecurityTokenReference in KeyInfo
signed_bytes = sign_envelope_bsp(envelope_bytes, private_key, certificate)

# Verify — extracts cert from BST, verifies ds:Signature
verified_bytes = verify_envelope_bsp(signed_bytes)

# Build a standalone BinarySecurityToken element (e.g. to add to an existing header)
bst = build_binary_security_token(certificate, token_id="MyToken-1")
```

---

## MTOM/XOP

soapbar supports MTOM (Message Transmission Optimization Mechanism, W3C) for sending and receiving SOAP messages with binary attachments. The `multipart/related` MIME packaging is handled transparently — the core envelope sees resolved base64 data; your service code sees plain bytes.

### Client — sending attachments

```python
from soapbar import SoapClient, BindingStyle

client = SoapClient.manual(
    "http://localhost:8000/soap",
    binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
    use_mtom=True,
)

# Queue a binary attachment and get its Content-ID back
cid = client.add_attachment(b"\x89PNG...", content_type="image/png")

# The call packages the envelope + attachments as multipart/related
result = client.call("UploadImage", image_cid=cid, filename="logo.png")
```

### Server — receiving MTOM

No configuration required. `AsgiSoapApp` and `WsgiSoapApp` automatically detect inbound `multipart/related` requests, resolve all `xop:Include` references inline, and pass the reconstructed XML to the dispatcher as a normal SOAP envelope.

### Low-level API

```python
from soapbar import parse_mtom, build_mtom, MtomAttachment

# Parse a raw MTOM HTTP body
msg = parse_mtom(raw_bytes, content_type_header)
print(msg.soap_xml)       # bytes — envelope with XOP includes resolved
print(msg.attachments)    # list[MtomAttachment]

# Build a MTOM HTTP body
attachments = [MtomAttachment(content_id="part1@host", content_type="image/png", data=png_bytes)]
body_bytes, content_type = build_mtom(soap_xml_bytes, attachments)
```
