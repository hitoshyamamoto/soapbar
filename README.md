# soapbar

![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![License](https://img.shields.io/badge/license-MIT%20with%20Attribution-green)
![Coverage](https://img.shields.io/badge/coverage-passing-brightgreen)

A SOAP framework for Python — client, server, and WSDL handling.

soapbar implements SOAP 1.1 and 1.2 with all five binding styles, auto-generates WSDL from Python service classes, parses existing WSDL to drive a typed client, and integrates with any ASGI or WSGI framework via thin adapter classes. The XML parser is hardened against XXE attacks using lxml with `resolve_entities=False`.

---

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Quick start — server](#quick-start--server)
4. [Binding styles and SOAP encoding](#binding-styles-and-soap-encoding)
5. [Defining a service](#defining-a-service)
6. [SOAP versions](#soap-versions)
7. [Framework compatibility](#framework-compatibility)
8. [WSDL](#wsdl)
9. [Client](#client)
10. [XSD type system](#xsd-type-system)
11. [Fault handling](#fault-handling)
12. [Security](#security)
13. [Interoperability](#interoperability)
14. [Architecture](#architecture)
15. [Public API](#public-api)
16. [Comparison with alternatives](#comparison-with-alternatives)
17. [Development setup](#development-setup)
18. [Inspired by](#inspired-by)
19. [Learn more](#learn-more)
20. [Known Limitations](#known-limitations)
21. [License](#license)

---

## Features

- SOAP 1.1 and 1.2 (auto-detected from envelope namespace; fault codes auto-translated)
- All 5 WSDL/SOAP binding style combinations (RPC/Encoded, RPC/Literal, Document/Literal, Document/Literal/Wrapped, Document/Encoded)
- Auto-generates WSDL from service class definitions — no config files needed
- Parses existing WSDL to drive a typed client
- ASGI adapter (`AsgiSoapApp`) and WSGI adapter (`WsgiSoapApp`)
- ⚠️ XXE-safe hardened XML parser (lxml, `resolve_entities=False`, `no_network=True`, `load_dtd=False`)
- XSD type registry with 27 built-in types
- Sync and async HTTP client (httpx optional)
- Interoperable with zeep and spyne out-of-the-box (verified by integration tests)
- Full type annotations + `py.typed` marker (PEP 561)
- Python 3.10 – 3.14

---

## Installation

```bash
pip install soapbar           # core + server + WSDL (lxml only)
pip install soapbar[core]     # explicit alias for the above
pip install soapbar[server]   # explicit alias for the above
pip install soapbar[client]   # + httpx for the HTTP client
pip install soapbar[all]      # everything (same as [client] today)
```

Or with uv:

```bash
uv add soapbar
uv add "soapbar[client]"
uv add "soapbar[all]"
```

---

## Quick start — server

### Variant A — standalone (bare ASGI, no framework)

```python
# app.py
from soapbar import SoapService, soap_operation, SoapApplication, AsgiSoapApp


class CalculatorService(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calculator"

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation()
    def subtract(self, a: int, b: int) -> int:
        return a - b


soap_app = SoapApplication(service_url="http://localhost:8000")
soap_app.register(CalculatorService())

app = AsgiSoapApp(soap_app)
# Run: uvicorn app:app --port 8000
# WSDL: GET http://localhost:8000?wsdl
```

### Variant B — mounted inside FastAPI

```python
from fastapi import FastAPI
from soapbar import SoapApplication, AsgiSoapApp

# ... (same CalculatorService class as above) ...

soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

api = FastAPI()
api.mount("/soap", AsgiSoapApp(soap_app))
# Run: uvicorn app:api --port 8000
# WSDL: GET http://localhost:8000/soap?wsdl
```

---

## Binding styles and SOAP encoding

### Background — two dimensions

The WSDL `<binding>` element is described by two orthogonal choices:

- **Style:** `rpc` or `document` — controls whether the SOAP Body contains a wrapper element named after the operation (`rpc`) or raw parameter elements without a wrapper (`document`).
- **Use:** `encoded` or `literal` — controls whether each element carries a `xsi:type` attribute with runtime type information (`encoded`) or relies solely on the schema (`literal`).

References:
- [IBM developerWorks — Which WSDL style?](https://developer.ibm.com/articles/ws-whichwsdl/)
- [DZone — Different SOAP encoding styles](https://dzone.com/articles/different-soap-encoding-styles)
- [Stack Overflow — Document vs RPC style](https://stackoverflow.com/questions/9062475/what-is-the-difference-between-document-style-and-rpc-style-communication)

### The five combinations

`BindingStyle` is importable as `from soapbar import BindingStyle`.

| `BindingStyle` enum | WSDL style | WSDL use | WS-I BP | Notes |
|---|---|---|---|---|
| `RPC_ENCODED` | rpc | encoded | ✗ | Legacy; params carry `xsi:type`; operation wrapper in Body |
| `RPC_LITERAL` | rpc | literal | ✓ | No `xsi:type`; operation wrapper in Body |
| `DOCUMENT_LITERAL` | document | literal | ✓ | Params are direct Body children; no wrapper |
| `DOCUMENT_LITERAL_WRAPPED` | document | literal | ✓ | **Default & recommended**; single wrapper element named after operation |
| `DOCUMENT_ENCODED` | document | encoded | ✗ | Params are direct Body children each with `xsi:type` |

#### RPC_ENCODED

```xml
<soapenv:Body>
  <tns:add soapenc:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <a xsi:type="xsd:int">3</a>
    <b xsi:type="xsd:int">5</b>
  </tns:add>
</soapenv:Body>
```

#### RPC_LITERAL

```xml
<soapenv:Body>
  <tns:add>
    <a>3</a>
    <b>5</b>
  </tns:add>
</soapenv:Body>
```

#### DOCUMENT_LITERAL

```xml
<soapenv:Body>
  <a>3</a>
  <b>5</b>
</soapenv:Body>
```

#### DOCUMENT_LITERAL_WRAPPED (default)

```xml
<soapenv:Body>
  <tns:add>
    <a>3</a>
    <b>5</b>
  </tns:add>
</soapenv:Body>
```

#### DOCUMENT_ENCODED

```xml
<soapenv:Body>
  <a xsi:type="xsd:int">3</a>
  <b xsi:type="xsd:int">5</b>
</soapenv:Body>
```

### Which to choose?

Use `DOCUMENT_LITERAL_WRAPPED` unless you are interoperating with a legacy system that requires `RPC_ENCODED`. `DOCUMENT_LITERAL_WRAPPED` is WS-I Basic Profile compliant, the most widely supported style, and the easiest to validate with schema tools.

---

## Defining a service

```python
from decimal import Decimal
from soapbar import SoapService, soap_operation, BindingStyle, SoapVersion, xsd
from soapbar import OperationParameter


class PricingService(SoapService):
    # Class attributes (all have defaults — only override what you need)
    __service_name__ = "Pricing"
    __tns__ = "http://example.com/pricing"
    __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED
    __soap_version__ = SoapVersion.SOAP_11
    __service_url__ = "http://localhost:8000/soap"

    # Auto-introspection: input/output params derived from type hints
    @soap_operation(documentation="Calculate discounted price")
    def get_price(self, item_id: str, quantity: int) -> Decimal:
        return Decimal("9.99") * quantity

    # Explicit params: use when hints are insufficient or unavailable
    @soap_operation(
        input_params=[
            OperationParameter(name="item_id", xsd_type=xsd.resolve("string")),
            OperationParameter(name="quantity", xsd_type=xsd.resolve("int")),
        ],
        output_params=[
            OperationParameter(name="price", xsd_type=xsd.resolve("decimal")),
        ],
    )
    def get_price_explicit(self, item_id: str, quantity: int) -> Decimal:
        return Decimal("9.99") * quantity
```

### `SoapService` class attribute defaults

| Attribute | Default | Notes |
|---|---|---|
| `__service_name__` | class name | Used in WSDL `<service name="">` |
| `__tns__` | `"http://example.com/{name}"` | Target namespace |
| `__binding_style__` | `BindingStyle.DOCUMENT_LITERAL_WRAPPED` | Recommended default |
| `__soap_version__` | `SoapVersion.SOAP_11` | Change to `SOAP_12` if needed |
| `__port_name__` | `"{name}Port"` | WSDL port name |
| `__service_url__` | `""` | Override or pass to `SoapApplication` |

---

## SOAP versions

| | SOAP 1.1 | SOAP 1.2 |
|---|---|---|
| Envelope namespace | `http://schemas.xmlsoap.org/soap/envelope/` | `http://www.w3.org/2003/05/soap-envelope` |
| Content-Type | `text/xml; charset=utf-8` | `application/soap+xml; charset=utf-8` |
| Action header | `SOAPAction: "..."` (separate header) | `action="..."` in Content-Type |
| Fault code (client) | `Client` | `Sender` |
| Fault code (server) | `Server` | `Receiver` |

soapbar detects the SOAP version automatically from the envelope namespace and translates fault codes between versions when building responses.

```python
from soapbar import SoapVersion

SoapVersion.SOAP_11   # SOAP 1.1
SoapVersion.SOAP_12   # SOAP 1.2
```

---

## Framework compatibility

### ASGI frameworks (via `AsgiSoapApp`)

`AsgiSoapApp` is a standard ASGI application. Mount it anywhere an ASGI app is accepted.

| Framework | How to mount |
|---|---|
| **FastAPI** | `app.mount("/soap", AsgiSoapApp(soap_app))` |
| **Starlette** | `routes=[Mount("/soap", app=AsgiSoapApp(soap_app))]` |
| **Litestar** | `app.mount("/soap", AsgiSoapApp(soap_app))` |
| **Quart** | Use `asgiref` or serve directly with Hypercorn |
| **BlackSheep** | `app.mount("/soap", AsgiSoapApp(soap_app))` |
| **Django** (≥ 3.1 ASGI) | Route in `asgi.py` via URL dispatcher |

ASGI servers (Uvicorn, Hypercorn, Daphne) can run `AsgiSoapApp` directly.

**FastAPI example:**

```python
from fastapi import FastAPI
from soapbar import SoapApplication, AsgiSoapApp

soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

api = FastAPI()
api.mount("/soap", AsgiSoapApp(soap_app))
```

### WSGI frameworks (via `WsgiSoapApp`)

| Framework | How to mount |
|---|---|
| **Flask** | `DispatcherMiddleware` or replace `app.wsgi_app` (requires `werkzeug`) |
| **Django** (classic WSGI) | Mount as sub-application in `urls.py` |
| **Falcon** | `app.add_sink(WsgiSoapApp(soap_app), "/soap")` |
| **Bottle** | `app.mount("/soap", WsgiSoapApp(soap_app))` |
| **Pyramid** | Composable WSGI stack |

WSGI servers (Gunicorn, uWSGI, mod_wsgi) can run `WsgiSoapApp` directly.

**Flask example:**

```python
from flask import Flask
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from soapbar import SoapApplication, WsgiSoapApp

soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

flask_app = Flask(__name__)
flask_app.wsgi_app = DispatcherMiddleware(flask_app.wsgi_app, {
    "/soap": WsgiSoapApp(soap_app),
})
```

---

## WSDL

**Auto-generation** — no configuration needed. Register a service and the WSDL is generated automatically:

```python
wsdl_bytes = soap_app.get_wsdl()
```

Served automatically at `GET ?wsdl` when using `AsgiSoapApp` or `WsgiSoapApp`.

**Parse an existing WSDL** to inspect its structure:

```python
from soapbar import parse_wsdl, parse_wsdl_file

defn = parse_wsdl(wsdl_bytes)          # from bytes/str
defn = parse_wsdl_file("service.wsdl") # from file
```

**Custom WSDL override** — supply your own WSDL document and skip auto-generation:

```python
soap_app = SoapApplication(custom_wsdl=open("my_service.wsdl", "rb").read())
```

---

## Client

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

### `HttpTransport` options

```python
from soapbar import SoapClient, HttpTransport

transport = HttpTransport(timeout=60.0, verify_ssl=False)
client = SoapClient(wsdl_url="http://localhost:8000/soap?wsdl", transport=transport)
```

### Advanced: manual client with explicit operation signature

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

---

## XSD type system

soapbar includes a registry of 27 built-in XSD types. Types handle serialization to and from XML text.

```python
from soapbar import xsd

# Resolve a type by XSD name
int_type = xsd.resolve("int")        # XsdType for xsd:int
str_type = xsd.resolve("string")     # XsdType for xsd:string

# Map a Python type to its XSD equivalent
xsd_type = xsd.python_to_xsd(int)    # -> xsd:int XsdType
xsd_type = xsd.python_to_xsd(str)    # -> xsd:string XsdType

# Serialize / deserialize
int_type.to_xml(42)       # "42"
int_type.from_xml("42")   # 42

# Inspect all registered types
all_types = xsd.all_types()
```

Python → XSD mapping:

| Python type | XSD type |
|---|---|
| `bool` | `boolean` |
| `int` | `int` |
| `float` | `float` |
| `str` | `string` |
| `Decimal` | `decimal` |
| `bytes` | `base64Binary` |

---

## Fault handling

### Raising a fault from a service method

```python
from soapbar import SoapService, soap_operation, SoapFault


class StrictCalculator(SoapService):
    __service_name__ = "StrictCalculator"
    __tns__ = "http://example.com/calc"

    @soap_operation()
    def divide(self, a: int, b: int) -> int:
        if b == 0:
            raise SoapFault(
                faultcode="Client",
                faultstring="Division by zero",
                detail="b must be non-zero",
            )
        return a // b
```

`SoapClient.call()` and `call_async()` automatically raise `SoapFault` when the server returns a fault response.

### Creating and rendering faults manually

```python
from soapbar import SoapFault

# Create a fault
fault = SoapFault(
    faultcode="Client",
    faultstring="Invalid input: quantity must be positive",
    detail="quantity=-1",          # string or lxml _Element
)

# Render as SOAP 1.1 or 1.2 envelope
envelope_11 = fault.to_soap11_envelope()
envelope_12 = fault.to_soap12_envelope()

# SOAP 1.2 subcodes
fault_12 = SoapFault(
    faultcode="Client",
    faultstring="Validation error",
    subcodes=["tns:InvalidQuantity"],
)
```

Fault code translation is automatic:

| Canonical (used in soapbar) | SOAP 1.1 wire | SOAP 1.2 wire |
|---|---|---|
| `Client` | `Client` | `Sender` |
| `Server` | `Server` | `Receiver` |

---

## Security

⚠️ soapbar uses a hardened lxml parser with the following settings:

```python
lxml.etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
)
```

Entity references (potential XXE payloads) are silently dropped rather than expanded. No network connections are made during parsing. DTDs are not loaded.

---

## Interoperability

soapbar is tested against zeep and spyne via integration tests.

- **zeep → soapbar**: a zeep client can call a soapbar server without modification. The WSDL generated by soapbar is zeep-parseable.
- **soapbar → spyne**: a soapbar client can call a spyne server using RPC/Literal.
- **soapbar ↔ soapbar**: full round-trip tested for all binding styles and both SOAP versions.

---

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
| `HttpTransport` | `from soapbar import HttpTransport` | HTTP transport layer |
| `SoapFault` | `from soapbar import SoapFault` | SOAP fault exception |
| `BindingStyle` | `from soapbar import BindingStyle` | Binding style enum |
| `SoapVersion` | `from soapbar import SoapVersion` | SOAP version enum |
| `xsd` | `from soapbar import xsd` | XSD type registry |
| `parse_wsdl` | `from soapbar import parse_wsdl` | Parse WSDL from bytes/str |
| `parse_wsdl_file` | `from soapbar import parse_wsdl_file` | Parse WSDL from a file path |
| `build_wsdl_string` | `from soapbar import build_wsdl_string` | Generate WSDL as string |
| `OperationParameter` | `from soapbar import OperationParameter` | Parameter descriptor for operations |
| `OperationSignature` | `from soapbar import OperationSignature` | Full operation signature (manual client) |

---

## Comparison with alternatives

| Capability | **soapbar** | zeep | spyne | fastapi-soap |
|---|---|---|---|---|
| SOAP client | ✓ | ✓ | ✗ | ✗ |
| SOAP server | ✓ | ✗ | ✓ | ✓ |
| All 5 binding styles | ✓ | ✓ (client) | ✓ | Partial |
| SOAP 1.1 + 1.2 | ✓ | ✓ | ✓ | 1.1 only |
| ASGI frameworks | ✓ | ✗ | ✗ | FastAPI only |
| WSGI frameworks | ✓ | ✗ | ✓ | ✗ |
| Auto WSDL generation | ✓ | ✗ | ✓ | ✓ |
| WSDL-driven client | ✓ | ✓ | ✗ | ✗ |
| XXE hardened by default | ✓ | ? | ? | ? |
| Core dependency | lxml | lxml, requests | lxml | fastapi, lxml |
| Async HTTP client | httpx (optional) | httpx (optional) | — | — |
| Python versions | 3.10–3.14 | 3.8+ | 3.8+ | 3.8+ |

soapbar is the only Python library that covers both client and server, works with any ASGI or WSGI framework, supports SOAP 1.1 and 1.2, and is hardened against XXE attacks out of the box.

---

## Development setup

```bash
git clone https://github.com/hitoshyamamoto/soapbar
cd soapbar
uv sync --group dev --group lint --group type

# Run tests
uv run pytest tests/ -v

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/
```

Run the example server (requires FastAPI + uvicorn):

```bash
pip install fastapi uvicorn
uvicorn examples.calculator_fastapi:app --reload --port 8000
```

Then fetch the WSDL: `curl http://localhost:8000/soap?wsdl`

---

## Inspired by

- **[Spyne](https://github.com/arskom/spyne)** — the original comprehensive Python SOAP/RPC framework; inspired the service-class model and binding style abstractions.
- **[zeep](https://github.com/mvantellingen/python-zeep)** — the de facto modern Python SOAP client; inspired the WSDL-driven client approach and XSD type mapping.
- **[fastapi-soap](https://github.com/rezashahnazar/fastapi-soap)** — demonstrated clean FastAPI/ASGI integration for SOAP endpoints; inspired the ASGI adapter design.

---

## Learn more

**SOAP protocol**
- [Wikipedia — SOAP](https://pt.wikipedia.org/wiki/SOAP)
- [W3Schools — XML/SOAP intro](https://www.w3schools.com/XML/)
- [GeeksForGeeks — Basics of SOAP](https://www.geeksforgeeks.org/computer-networks/basics-of-soap-simple-object-access-protocol/)
- [Oracle — SOAP API reference](https://docs.oracle.com/en/cloud/saas/applications-common/25a/biacc/soap-api.html)

**WSDL**
- [TutorialsPoint — WSDL](https://www.tutorialspoint.com/wsdl/index.htm)
- [GeeksForGeeks — WSDL introduction](https://www.geeksforgeeks.org/software-engineering/wsdl-introduction/)

**Binding styles and encoding**
- [IBM developerWorks — Which WSDL style?](https://developer.ibm.com/articles/ws-whichwsdl/)
- [DZone — Different SOAP encoding styles](https://dzone.com/articles/different-soap-encoding-styles)
- [Stack Overflow — Document vs RPC style](https://stackoverflow.com/questions/9062475/what-is-the-difference-between-document-style-and-rpc-style-communication)

---

## Known Limitations

The following features are intentionally out-of-scope for the current release.  Behaviour is well-defined in each case (documented exception or graceful exposure).

| Area | Status | Notes |
|------|--------|-------|
| **MTOM/XOP** | Detected; HTTP 415 + SOAP fault returned | Full multipart SOAP attachment processing is not implemented. If the client sends a `multipart/related` request that carries XOP, the server returns a `415 Unsupported Media Type` response with a SOAP fault. The transport layer raises `NotImplementedError` if an MTOM response is received. |
| **WS-Security** | Header element exposed, not processed | The `wsse:Security` header is detected and the raw element is available as `envelope.ws_security_element`. Signature verification, token validation, and encryption are out of scope. |
| **WS-Addressing** | Headers parsed into `WsaHeaders` dataclass | Inbound WS-Addressing headers (`MessageID`, `To`, `Action`, `ReplyTo`, `FaultTo`, etc.) are parsed and exposed on `envelope.ws_addressing`. The server does **not** automatically set `MessageID` or `Action` in response envelopes. |
| **SOAP 1.2 `relay` attribute** | Parsed and exposed on `SoapHeaderBlock` | The `relay` boolean is available on each `SoapHeaderBlock` instance. Full SOAP intermediary forwarding (actually relaying the message) is not implemented. |
| **`xsd:complexType` / `xsd:array` / `xsd:choice`** | Fully supported for round-trip serialization | Recursive (`self-referencing`) complex types are resolved lazily. `xsd:complexContent/restriction` for SOAP-encoded arrays is also parsed from WSDL. |
| **External schema `xsd:import`** | Not followed | `wsdl:import` (document-level) is resolved. `xsd:import` elements *inside* a `<types>` schema are silently ignored; type resolution falls back to built-in primitives. |

---

## License

MIT with Attribution
