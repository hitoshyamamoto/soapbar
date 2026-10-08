# Client

```python
import asyncio
from soapbar import SoapClient, SoapFault

# From a live WSDL URL (fetches WSDL over HTTP)
client = SoapClient(wsdl_url="http://localhost:8000/soap?wsdl")

# From a WSDL string/bytes you already have
client = SoapClient.from_wsdl_string(wsdl_bytes)

# From a WSDL file
client = SoapClient.from_file("service.wsdl")

# Manual — no WSDL, specify endpoint and style directly
from soapbar import BindingStyle, SoapVersion

client = SoapClient.manual(
    address="http://localhost:8000/soap",
    binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
    soap_version=SoapVersion.SOAP_11,
)

# Sync call via service proxy
try:
    result = client.service.add(a=3, b=5)
    print(result)  # 8
except SoapFault as fault:
    print(fault.faultcode, fault.faultstring)

# Direct call by operation name
result = client.call("add", a=3, b=5)

# Async call
async def main():
    result = await client.call_async("add", a=3, b=5)
    print(result)

asyncio.run(main())
```

## `HttpTransport` options

```python
from soapbar import SoapClient, HttpTransport

transport = HttpTransport(timeout=60.0, verify_ssl=False)
client = SoapClient(wsdl_url="http://localhost:8000/soap?wsdl", transport=transport)
```

### Mutual TLS (client certificate)

Services behind a private or government PKI require the client to present a
certificate on the TLS handshake, and often to verify the server against a
custom CA. Pass `client_cert` (a combined-PEM path, a `(certfile, keyfile)`
tuple, or in-memory `(cert_pem, key_pem)` bytes) and `ca_bundle`:

```python
from soapbar import HttpTransport, load_pkcs12

# From PEM files on disk:
transport = HttpTransport(
    client_cert=("client.pem", "client.key"),
    ca_bundle="private-ca.pem",
)

# Or from a PKCS#12 (.pfx) bundle (e.g. an ICP-Brasil A1 certificate) — the
# private key stays in memory and is never written to disk:
cert_pem, key_pem = load_pkcs12("certificate.pfx", "password")
transport = HttpTransport(client_cert=(cert_pem, key_pem), ca_bundle="private-ca.pem")
```

Mutual TLS requires httpx (`soapbar[client]`); `load_pkcs12` requires
`cryptography` (`soapbar[security]`).

### Session cookies

Stateful services keep a session across calls via cookies (e.g. a login that
returns `JSESSIONID`). When a transport is reused, its cookie jar persists, so
the session is carried automatically. Read or inject cookies via
`transport.cookies`:

```python
transport = HttpTransport()  # persist_cookies=True by default
client = SoapClient(wsdl_url="https://service/?wsdl", transport=transport)

client.call("Login", user="...", password="...")   # server sets JSESSIONID
print(transport.cookies.get("JSESSIONID"))          # read it
client.call("DoWork", ...)                          # cookie sent automatically
client.call("Logout")

# Or inject a session cookie obtained out of band:
transport.cookies.set("JSESSIONID", "abc123", domain="service")
```

Pass `HttpTransport(persist_cookies=False)` for stateless behaviour — the jar
is cleared after every call. Session cookies require httpx (`soapbar[client]`).

### Response size limit

MTOM/XOP decoding of a response is bounded by
`HttpTransport(max_response_size=10 * 1024 * 1024)` (10 MB, mirroring the
server's `max_body_size`). A response can reference one small attachment from
many `xop:Include` elements, so the *resolved* size can be far larger than the
bytes on the wire; decoding stops with `BodyTooLargeError` as soon as the
running resolved total crosses the cap, before the amplified result is
allocated. The cap bounds XOP resolution — it is not a limit on the raw HTTP
download itself.

### Raw exchange capture (archival)

Some integrations are legally required to retain exactly what crossed the
wire — Brazilian fiscal documents, for instance, carry a five-year retention
obligation for the XML as sent and as received. `on_exchange` fires on every
send, success or HTTP error, with the exact wire bytes:

```python
def archive(request: bytes, response: bytes, url: str, headers: dict) -> None:
    store.save(url=url, sent=request, received=response)   # your storage

transport = HttpTransport(on_exchange=archive)
client = SoapClient(wsdl_url="https://example.com/soap?wsdl", transport=transport)
```

The callback is stateless and safe under concurrency; an exception it raises
propagates — a failed archive must be visible, never swallowed. The captured
request is the body as sent (after MTOM packaging); the captured response is
the body as received (before MTOM decoding). WSDL retrieval (`fetch()`) is
not part of the exchange capture.

For quick debugging, `transport.last_request` / `transport.last_response`
mirror the most recent exchange — per-transport state, not thread-safe; use
the callback for anything concurrent or durable.

## Errors a call can raise

Everything soapbar raises deliberately derives from `SoapbarError`, so one
`except SoapbarError` catches any library-originated failure. The specific
types worth distinguishing on the client side:

| Exception | When |
|---|---|
| `SoapFault` | The peer answered with a SOAP Fault. `faultcode`, `faultstring` and `detail` carry what it said. |
| `NonSoapResponseError` | The response is not a SOAP envelope at all — a proxy's HTML error page, an auth challenge, a gateway's JSON error, an empty body. Carries the HTTP `status`, the `content_type` and a truncated `body_excerpt`; read the excerpt first, it usually names the real problem. |
| `WsdlFetchError` | WSDL retrieval (`SoapClient(wsdl_url=...)`, `HttpTransport.fetch`) answered with a non-2xx status. Raised on both the httpx and the urllib path, with the stack's own exception as `__cause__`, and carries `url` and `status`. |
| `BodyTooLargeError` | A response's XOP-resolved size crossed `max_response_size`, or a remote WSDL import exceeded its 10 MB read ceiling. Also a `ValueError`. |
| `ValueError` | Calling an operation the client does not know (keyword arguments would be silently dropped otherwise — pass `allow_unknown=True` to send a bare request deliberately), a URL with a scheme other than `http`/`https`, or a remote/local import the parser was not allowed to follow. |

Transport-level failures that are not HTTP responses — DNS, connection refused,
TLS handshake, timeouts — propagate from the HTTP stack unchanged
(`httpx.ConnectError`, `httpx.ReadTimeout`, `urllib.error.URLError`).
Diagnosing them is covered in the [debugging guide](debugging.md).

```python
from soapbar import SoapbarError, SoapClient, SoapFault, NonSoapResponseError

try:
    result = client.service.Add(a=3, b=5)
except SoapFault as fault:
    ...                         # the service said no: fault.faultcode / faultstring
except NonSoapResponseError as err:
    ...                         # something between you and the service answered: err.status, err.body_excerpt
except SoapbarError:
    ...                         # anything else soapbar raised on purpose
```

## Advanced: manual client with explicit operation signature

Use `register_operation` when you need full control over the operation schema without a WSDL:

```python
from soapbar import SoapClient, OperationSignature, OperationParameter, BindingStyle, xsd

sig = OperationSignature(
    name="Add",
    input_params=[
        OperationParameter("a", xsd.resolve("int")),
        OperationParameter("b", xsd.resolve("int")),
    ],
    output_params=[OperationParameter("return", xsd.resolve("int"))],
)

client = SoapClient.manual("http://host/soap", binding_style=BindingStyle.RPC_LITERAL)
client.register_operation(sig)
result = client.call("Add", a=3, b=4)  # 7
```
