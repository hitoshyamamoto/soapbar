# Security Notes

This document describes the trust model, known limitations, and intentional design decisions
for soapbar. For the responsible-disclosure policy (how to report vulnerabilities), see
[`.github/SECURITY.md`](.github/SECURITY.md).

---

## Certificate trust (X.509 / WS-Security)

soapbar validates the notBefore / notAfter validity window of X.509 certificates presented
in `wsse:BinarySecurityToken` headers, but it does **not** perform:

- CRL (Certificate Revocation List) checking
- OCSP (Online Certificate Status Protocol) queries
- Certificate path / chain building against a trust anchor store

**Deployers must pre-validate the certificate chain out-of-band** before handing a certificate
to `verify_envelope_bsp()` or to any WS-Security credential. For example, verify the full
chain against your CA trust store using `cryptography`'s `X509Store` or OpenSSL before calling
soapbar's verification API.

A future release may expose a `certificate_validator: Callable[[x509.Certificate], None]`
hook in `verify_envelope_bsp()` to let callers plug in custom chain-validation logic.

---

## PasswordDigest and SHA-1

The `PasswordDigest` token type computes:

```
Base64( SHA-1( nonce || created || password ) )
```

This formula is **mandated by OASIS WSS 1.0 UsernameToken Profile §3.2.1**. The use of SHA-1
here is a spec requirement, not a design choice, and cannot be changed without breaking
interoperability with all OASIS-conformant peers (WSS4J, WCF, CXF, etc.).

If your threat model requires a stronger digest, use X.509 token-based message signing
(`sign_envelope_bsp`) instead of UsernameToken/PasswordDigest.

---

## PasswordText and transport security

soapbar rejects `#PasswordText` UsernameToken credentials by default when the configured
`service_url` uses plain HTTP (WSS 1.0 §6.2; WS-I BSP R4202). This protection can be
overridden for local development only by passing `allow_plaintext_credentials=True` to
`SoapApplication`.

For production deployments, either:
- Terminate TLS at the WSGI/ASGI host and set `service_url` to an `https://` URL, or
- Switch to `PasswordDigest` credentials, which do not expose the raw password in transit.

---

## Encoding

soapbar always serialises outbound envelopes as UTF-8. Inbound envelopes encoded in UTF-16
will fail to parse. UTF-8-only output is conformant with WS-I Basic Profile 1.1 R2710, which
permits UTF-8 or UTF-16; the practical universe of SOAP peers sends UTF-8.

---

## Fault Detail on header faults

SOAP 1.1 §4.4 states that the `Detail` element SHOULD NOT be present when a fault was caused
by a header, not the body. soapbar allows the caller to supply a `detail` argument to
`SoapFault` regardless of fault category. This is a deliberate permissive choice; the word
"SHOULD NOT" does not prohibit the behaviour.

---

## Timeouts and concurrency limits

soapbar does not enforce per-request read/write timeouts or connection concurrency limits.
These are the responsibility of the WSGI/ASGI host:

- **uvicorn**: `--timeout-keep-alive`, `--limit-concurrency`
- **gunicorn**: `--timeout`, `--workers`
- **hypercorn**: `--graceful-timeout`, `--workers`

Deployers should configure suitable values at the host layer before exposing a soapbar
service on a public network.
