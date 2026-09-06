# Deployment

What to configure before a soapbar service faces a network: the limits the
host layer must own, and the knobs soapbar itself provides.

## Host-layer limits

soapbar does not enforce per-request read/write timeouts or connection
concurrency limits — those belong to the WSGI/ASGI host:

- **uvicorn**: `--timeout-keep-alive`, `--limit-concurrency`
- **gunicorn**: `--timeout`, `--workers`
- **hypercorn**: `--graceful-timeout`, `--workers`

Configure suitable values before exposing a service on a public network, and
terminate TLS at the host (or in front of it) — `SoapApplication` warns at
construction when `service_url` is plain HTTP.

## soapbar's own knobs

All keyword-only on `SoapApplication(...)`:

| Knob | Default | What it bounds |
|---|---|---|
| `max_body_size` | 10 MB | Raw request bytes, gzip-decompressed size (bomb guard), and MTOM/XOP resolved size — rejected with a `Client` fault before parsing. |
| `enable_gzip` | off | HTTP-level request decompression / response compression. Inbound codings are matched exactly (`gzip`/`x-gzip`/`identity`); anything else is a `Client` fault. |
| `validate_body_schema` | off | Validates each Body element against the schema the published WSDL advertises, before deserialization. Wrapped binding styles only — registering a non-wrapped service with the flag on raises `ValueError`. See [WSDL schema validation](wsdl.md#wsdl-schema-validation). |
| `security_validator` | none | WS-Security UsernameToken validation, including timestamp expiry and nonce replay windows. |
| `allow_plaintext_credentials` | off | Development-only override for PasswordText over plain HTTP. |
| `wsdl_access` | `"public"` | `?wsdl` exposure: `public`, `authenticated` (via `wsdl_auth_hook`), or `disabled`. |

Two limits are fixed rather than parameters, so there is no knob to hunt for:

- **XML nesting depth** is capped at 100 levels (`check_xml_depth`'s
  default); deeper documents are rejected before a tree is built.
- **`xsd:import`/`xsd:include` recursion** is capped at 8 levels
  (`_MAX_XSD_IMPORT_DEPTH`) during WSDL parsing.

## WSDL parsing at deploy time

If your deployment parses WSDLs (a gateway, a client fleet), the import
resolver is closed by default: remote imports require
`parse_wsdl(..., allow_remote_imports=True)`, local reads outside
`parse_wsdl_file`'s document tree are refused, redirects are never followed,
and remote fetches time out after 30 s. The full posture, with its
executable evidence, is in
[SECURITY.md](https://github.com/hitoshyamamoto/soapbar/blob/main/SECURITY.md).

On the client side, `HttpTransport(timeout=..., max_response_size=...)`
bounds the request timeout (default 30 s) and the MTOM/XOP-resolved size of
responses (default 10 MB).

## Checklist

1. TLS terminated at the host; `service_url` is `https://`.
2. Host timeouts and concurrency limits set (flags above).
3. `max_body_size` sized for your realistic payloads, not left at 10 MB by
   ritual — smaller is better if your messages are small.
4. `wsdl_access` decided deliberately: a public WSDL is service
   documentation; `authenticated`/`disabled` fit internal services.
5. A `security_validator` (or transport-layer auth) in front of anything
   that mutates state.
6. Error scrubbing is on by default — unhandled exceptions return
   `"An internal error occurred."` — so log sinks, not clients, get your
   tracebacks. See [Debugging](debugging.md) for turning detail on locally.
