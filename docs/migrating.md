# Migrating from zeep or spyne

This page is a map, not an argument: it assumes you have already decided to
try soapbar and shows where each thing you use in zeep or spyne lives here.
Where zeep or spyne does something soapbar does not, the page says so.

## zeep → soapbar (client)

| zeep | soapbar |
|---|---|
| `zeep.Client(wsdl_url)` | `SoapClient(wsdl_url=...)` |
| `zeep.Client("service.wsdl")` | `SoapClient(wsdl_url="service.wsdl")` (a path works) |
| WSDL held in memory | `SoapClient.from_wsdl_string(wsdl_bytes)` |
| `client.service.Op(a=1)` | `client.service.Op(a=1)` (or `client.call("Op", a=1)`) |
| `zeep.AsyncClient` | `await client.call_async("Op", a=1)` |
| `Transport(session=...)` for TLS/timeouts | `HttpTransport(timeout=..., verify_ssl=..., client_cert=..., ca_bundle=...)` |
| `Settings(strict=False)` | `parse_wsdl(..., strict=False)` for lenient import resolution |
| `Settings(forbid_external=True)` | the default — see the callout below |

```python
from soapbar import SoapClient, HttpTransport

transport = HttpTransport(timeout=60.0, client_cert=("cert.pem", "key.pem"))
client = SoapClient(wsdl_url="https://example.com/service?wsdl", transport=transport)
result = client.service.Add(a=3, b=4)
```

**Seeing the raw XML.** zeep's `HistoryPlugin` has no direct equivalent;
soapbar logs full request and response envelopes at `DEBUG` on the
`soapbar.client.client` and `soapbar.client.transport` loggers, with
credentials redacted before they reach the log record:

```python
import logging
logging.getLogger("soapbar.client").setLevel(logging.DEBUG)
```

**Plugins.** zeep's ingress/egress plugin pipeline has no soapbar
equivalent. If you rewrite envelopes in a plugin today, the migration path is
wrapping `HttpTransport.send` (subclass it) — there is no hook API.

**The `_binding._operations` workaround.** When zeep cannot parse a response,
a common workaround reaches into `client.service._binding._operations` to
patch the operation. soapbar's supported form of the same move is explicit:
build the signature yourself and register it.

```python
from soapbar import SoapClient
from soapbar.core.binding import OperationParameter, OperationSignature
from soapbar.core.types import xsd

client = SoapClient.manual("https://example.com/soap")   # no WSDL at all
client.register_operation(OperationSignature(
    name="Add",
    input_params=[OperationParameter("a", xsd.resolve("int")),
                  OperationParameter("b", xsd.resolve("int"))],
    output_params=[OperationParameter("return", xsd.resolve("int"))],
    soap_action="Add",
))
```

**What zeep has that soapbar does not**: a WSDL/schema cache
(`SqliteCache`), the plugin pipeline, and a deeper XSD object model for
attribute-heavy schemas. If your integration leans on those, check the
[known limitations](limitations.md) page before committing.

## spyne → soapbar (server)

| spyne | soapbar |
|---|---|
| `ServiceBase` | `SoapService` |
| `@rpc(Integer, Integer, _returns=Integer)` | `@soap_operation()` + Python type hints |
| `Application(services, tns, in_protocol=Soap11(...), ...)` | `SoapApplication(service_url=...)` + `app.register(Svc())` |
| `WsgiApplication(app)` | `WsgiSoapApp(soap_app)` |
| ASGI | `AsgiSoapApp(soap_app)` (spyne has no ASGI adapter) |
| `?wsdl` | `?wsdl` (served by both adapters) |

```python
from soapbar import AsgiSoapApp, SoapApplication, SoapService, soap_operation

class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

soap_app = SoapApplication(service_url="https://example.com/soap")
soap_app.register(Calculator())
app = AsgiSoapApp(soap_app)          # or WsgiSoapApp(soap_app)
```

Types come from annotations (`int`, `str`, `float`, `bool`, `Decimal`,
`bytes`, `datetime`/`date`/`time`) instead of spyne's model classes; complex
types are declared as `ComplexXsdType` rather than `ComplexModel` subclasses.

A verifiable fact rather than a pitch: spyne does not import on
Python 3.12+ (its 2.14 release line predates the removal of long-deprecated
stdlib APIs), so a spyne service cannot follow its interpreter past 3.11
today. soapbar supports Python 3.10–3.14.

**What spyne has that soapbar does not**: the multi-protocol dispatch
(the same service over HTTP-RPC, JSON-RPC, MessagePack). soapbar is a SOAP
library; the only non-SOAP surface is opt-in JSON *responses* for clients
sending `Accept: application/json`.

## Behaviour differences that bite

- **Remote WSDL imports are blocked by default.** `parse_wsdl` raises on any
  `wsdl:import`/`xsd:import` that resolves to `http(s)://` unless you pass
  `allow_remote_imports=True` — a WSDL that "just worked" in zeep can raise
  `ValueError` here on first parse. This is deliberate (SSRF guard; see
  [SECURITY.md](https://github.com/hitoshyamamoto/soapbar/blob/main/SECURITY.md));
  the opt-in restores the zeep behaviour for trusted sources. Redirects are
  never followed during import resolution, and remote fetches time out after
  30 s.
- **Default binding style is document/literal wrapped** (zeep's most common
  case); RPC/literal, RPC/encoded, and bare document/literal are explicit
  opt-ins via `__binding_style__`.
- **`rpc:result` is off by default** on RPC responses, because strict zeep
  rejects it; `@soap_operation(emit_rpc_result=True)` turns it on for peers
  that require SOAP 1.2 §4.2.1 form.
- **Serialized children are unqualified** (`elementFormDefault="unqualified"`,
  declared honestly in the generated WSDL). Peers generated from the WSDL
  interoperate; hand-written payloads that qualify children via a default
  `xmlns` are rejected once `validate_body_schema=True` is on.
- **Fault status codes follow WS-I**: SOAP 1.1 faults return HTTP 500
  (including `Client` faults, per R1126); SOAP 1.2 `Sender` faults return 400.

The client-side snippets on this page run against zeep 4.3.3; the spyne
snippets follow its 2.14 documentation and are *not* executed by soapbar's CI,
since spyne does not import on the interpreters the suite runs on (its own
suite is exercised on Python ≤ 3.11 only).
