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
