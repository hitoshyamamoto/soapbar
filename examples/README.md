# soapbar Examples

Runnable, focused examples grouped by feature.  Every example is self-contained
and binds to `127.0.0.1` so it never exposes a socket outside the host.

| Folder | What it demonstrates |
|---|---|
| [`01_calculator/`](01_calculator/) | First-look SOAP 1.1 service on FastAPI and Flask; soapbar and zeep clients; SOAP Fault handling. |
| [`02_soap12/`](02_soap12/) | The same service upgraded to SOAP 1.2 — one attribute change. |
| [`03_wsdl_access_control/`](03_wsdl_access_control/) | X06 — serve the WSDL only to authenticated callers via `wsdl_access="authenticated"` + `wsdl_auth_hook`. |
| [`04_ws_security_signing/`](04_ws_security_signing/) | S04/S05 — sign an envelope with `sign_envelope_bsp` (Exclusive C14N + explicit `ds:Reference` for Body and Timestamp) and round-trip through `verify_envelope_bsp`. |
| [`05_ws_addressing/`](05_ws_addressing/) | A04 — WS-Addressing headers; using the `WSA_ANONYMOUS` / `WSA_NONE` magic-URI constants. |
| [`06_username_token_auth/`](06_username_token_auth/) | G09 — `UsernameTokenCredential` + `UsernameTokenValidator`; PasswordDigest over plain HTTP for local demos; how `allow_plaintext_credentials` opens the S08 gate. |
| [`07_mtom_attachments/`](07_mtom_attachments/) | MTOM/XOP `build_mtom` / `parse_mtom` round-trip; `xop:Include` resolution. |
| [`08_binding_styles/`](08_binding_styles/) | Side-by-side wire format for every `BindingStyle` (DLW, DL bare, RPC literal, RPC encoded, Document encoded). |
| [`09_async_client/`](09_async_client/) | `SoapClient.call_async` with `asyncio.gather` for concurrent requests. |
| [`10_complex_types/`](10_complex_types/) | `ComplexXsdType` request/response with a `User { name, email, age }` shape. |
| [`11_one_way_and_json/`](11_one_way_and_json/) | `@soap_operation(one_way=True)` returning HTTP 202; JSON dual-mode via `Accept: application/json`. |
| [`12_schema_validation/`](12_schema_validation/) | `validate_body_schema=True` — XSD-validate the SOAP Body before dispatch. |
| [`13_advanced_client/`](13_advanced_client/) | `SoapClient.manual()`, `from_file()`, and a custom `HttpTransport`. |
| [`14_security_replay_protection/`](14_security_replay_protection/) | N05 (Timestamp expiry) and N07 (nonce replay cache) in-process. |
| [`15_xml_encryption/`](15_xml_encryption/) | `encrypt_body` / `decrypt_body` round-trip (AES-256-CBC + RSA-OAEP-SHA256). |
| [`16_introspection/`](16_introspection/) | Inspect a `SoapEnvelope` (WS-A headers, fault status); walk a parsed `WsdlDefinition`. |

### Real-world services

These point soapbar at actual government/industry SOAP services. VIES and
WITSML run against live endpoints; NF-e and MeF are faithful references whose
`main()` prints guidance without touching the network — exercising them needs
external certificates/enrollment, but the soapbar features they use (mutual
TLS, session cookies, `Id`-targeted signing) are all shipped.

| Folder | Service | Auth | Runs live? |
|---|---|---|---|
| [`17_vies/`](17_vies/) | EU VIES VAT validation (`checkVat`) | none | ✅ yes (needs network) |
| [`18_witsml/`](18_witsml/) | WITSML 1.4.1.1 STORE API (RPC, manual ops) | WS-Security UsernameToken | ✅ yes (needs a WITSML server) |
| [`19_nfe/`](19_nfe/) | SEFAZ NF-e (`NFeStatusServico4`) | mutual TLS (ICP-Brasil) + `<infNFe>` Id-signing | reference (needs A1 cert + endpoint) |
| [`20_mef/`](20_mef/) | IRS MeF A2A | mutual TLS (Strong Auth) + session cookies | reference (needs IRS enrollment) |

## Running

Every example lists its own `uv run …` invocation in its module docstring.
Install the dev dependencies once:

```
uv sync --group dev
```

Optional extras the examples assume:

- `fastapi`, `uvicorn` — `01_calculator/server_fastapi.py`, most ASGI servers.
- `flask` — `01_calculator/server_flask.py`.
- `zeep` — `01_calculator/client_zeep.py` (interoperability demo).
- `cryptography` / `signxml` — `04_ws_security_signing/`, `19_nfe/` (bundled with `soapbar[security]`).

The `fastapi`/`uvicorn`/`flask` servers are also available via `uv sync --group examples`.

## Security note

The example servers use `http://` URLs for local convenience.  In production
always use `https://`: otherwise SOAP bodies, WS-Security `PasswordText`
credentials, and signed digests travel in plaintext, and `SoapApplication`
will refuse `PasswordText` over non-TLS unless you set
`allow_plaintext_credentials=True` (S08).
