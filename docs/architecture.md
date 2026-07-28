# Architecture and public API

## Architecture

```
  HTTP request
       │
       ▼
┌─────────────────┐
│ AsgiSoapApp /   │   ← thin ASGI/WSGI adapters
│ WsgiSoapApp     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ SoapApplication │   ← dispatcher: version detection,
│                 │     operation routing, fault wrapping
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SoapService    │   ← your business logic lives here
│  @soap_operation│
└────────┬────────┘
         │ calls binding serializer + envelope builder
         ▼
┌─────────────────┐
│  core/          │   ← binding.py · envelope.py · types.py
│  binding/types/ │       wsdl/ · xml.py · fault.py
│  envelope/wsdl  │
└─────────────────┘
```

---

## Public API

The most-used symbols are all importable from the top-level `soapbar` namespace:

| Symbol | Import | Description |
|--------|--------|-------------|
| `SoapService` | `from soapbar import SoapService` | Base class for SOAP services |
| `soap_operation` | `from soapbar import soap_operation` | Decorator for service methods |
| `SoapApplication` | `from soapbar import SoapApplication` | SOAP dispatcher/router |
| `AsgiSoapApp` | `from soapbar import AsgiSoapApp` | ASGI adapter |
| `WsgiSoapApp` | `from soapbar import WsgiSoapApp` | WSGI adapter |
| `SoapClient` | `from soapbar import SoapClient` | SOAP client |
| `HttpTransport` | `from soapbar import HttpTransport` | HTTP transport layer (timeout, mutual TLS, session cookies) |
| `load_pkcs12` | `from soapbar import load_pkcs12` | PKCS#12 (`.pfx`) → in-memory PEM `(cert, key)` for mutual TLS |
| `SoapFault` | `from soapbar import SoapFault` | SOAP fault exception |
| `BindingStyle` | `from soapbar import BindingStyle` | Binding style enum |
| `SoapVersion` | `from soapbar import SoapVersion` | SOAP version enum |
| `xsd` | `from soapbar import xsd` | XSD type registry |
| `parse_wsdl` | `from soapbar import parse_wsdl` | Parse WSDL from bytes/str |
| `parse_wsdl_file` | `from soapbar import parse_wsdl_file` | Parse WSDL from a file path |
| `build_wsdl_string` | `from soapbar import build_wsdl_string` | Generate WSDL as string |
| `OperationParameter` | `from soapbar import OperationParameter` | Parameter descriptor for operations |
| `OperationSignature` | `from soapbar import OperationSignature` | Full operation signature (manual client) |
| `UsernameTokenCredential` | `from soapbar.core.wssecurity import UsernameTokenCredential` | WS-Security credential for client |
| `UsernameTokenValidator` | `from soapbar.core.wssecurity import UsernameTokenValidator` | Abstract base for server-side token validation |
| `SecurityValidationError` | `from soapbar.core.wssecurity import SecurityValidationError` | Raised on authentication failure |
| `build_security_header` | `from soapbar.core.wssecurity import build_security_header` | Build `wsse:Security` header element |
| `sign_envelope` | `from soapbar.core.wssecurity import sign_envelope` | Enveloped XML-DSIG signature (RSA-SHA256) |
| `sign_element_by_id` | `from soapbar import sign_element_by_id` | Sign an inner element by its `Id` (configurable algorithms; e.g. SEFAZ NF-e) |
| `verify_envelope` | `from soapbar.core.wssecurity import verify_envelope` | Verify and return signed envelope bytes |
| `encrypt_body` | `from soapbar.core.wssecurity import encrypt_body` | AES-256-GCM authenticated body encryption + RSA-OAEP key wrap |
| `decrypt_body` | `from soapbar.core.wssecurity import decrypt_body` | Decrypt `xenc:EncryptedData` body and restore children |
| `XmlSecurityError` | `from soapbar.core.wssecurity import XmlSecurityError` | Raised on XML signature/encryption failure |
| `build_binary_security_token` | `from soapbar.core.wssecurity import build_binary_security_token` | Build WS-I BSP `wsse:BinarySecurityToken` from X.509 cert |
| `extract_certificate_from_security` | `from soapbar.core.wssecurity import extract_certificate_from_security` | Extract X.509 cert from `wsse:BinarySecurityToken` |
| `sign_envelope_bsp` | `from soapbar.core.wssecurity import sign_envelope_bsp` | BSP-compliant signing with `wsse:SecurityTokenReference` |
| `verify_envelope_bsp` | `from soapbar.core.wssecurity import verify_envelope_bsp` | Verify BSP-signed envelope using embedded BST cert |
| `MtomAttachment` | `from soapbar import MtomAttachment` | MTOM attachment descriptor (content_id, content_type, data) |
| `MtomMessage` | `from soapbar import MtomMessage` | Parsed MTOM message (soap_xml + attachments list) |
| `parse_mtom` | `from soapbar import parse_mtom` | Parse a raw `multipart/related` MTOM body |
| `build_mtom` | `from soapbar import build_mtom` | Build a `multipart/related` MTOM body |

**Real-world clients** (optional, under `soapbar.contrib.*` — see [Real-world services](real-world.md)):

| Symbol | Import | Description |
|--------|--------|-------------|
| `ViesClient` | `from soapbar.contrib.vies import ViesClient` | EU VIES VAT validation (`soapbar[vies]`) |
| `WitsmlClient` | `from soapbar.contrib.witsml import WitsmlClient` | WITSML 1.4.1.1 STORE API (`soapbar[witsml]`) |
| `NfeClient` | `from soapbar.contrib.nfe import NfeClient` | SEFAZ NF-e layout 4.00 (`soapbar[nfe]`) |
| `AnaClient` | `from soapbar.contrib.ana import AnaClient` | ANA ServiceANA telemetry, 12 ops (`soapbar[ana]`) |

**What's public and what you can rely on** — the public API is exactly the
top-level `soapbar` namespace plus the `soapbar.contrib.*` clients, pinned by a
snapshot test in CI. The contrib clients are a separate, lower stability tier
(they track externally-owned services). See
[`STABILITY.md`](https://github.com/hitoshyamamoto/soapbar/blob/main/STABILITY.md)
for the full surface definition, the SemVer policy, and the deprecation process.
