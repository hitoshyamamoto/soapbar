# soapbar

![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![License](https://img.shields.io/badge/license-MIT%20with%20Attribution-green)

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
13. [Inspired by](#inspired-by)
14. [Learn more](#learn-more)
15. [License](#license)

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

```python
# app.py
from soapbar.server.service import SoapService, soap_operation
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp


class CalculatorService(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calculator"

    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

    @soap_operation()
    def subtract(self, a: int, b: int) -> int:
        return a - b


soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

app = AsgiSoapApp(soap_app)
```

Run with uvicorn:

```bash
uvicorn app:app --port 8000
```

WSDL is available at `GET http://localhost:8000/soap?wsdl`.

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
from soapbar.server.service import SoapService, soap_operation
from soapbar.core.binding import BindingStyle, OperationParameter
from soapbar.core.envelope import SoapVersion
from soapbar.core.types import xsd


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
from soapbar.core.envelope import SoapVersion

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
from soapbar.server.application import SoapApplication
from soapbar.server.asgi import AsgiSoapApp

soap_app = SoapApplication(service_url="http://localhost:8000/soap")
soap_app.register(CalculatorService())

api = FastAPI()
api.mount("/soap", AsgiSoapApp(soap_app))
```

### WSGI frameworks (via `WsgiSoapApp`)

| Framework | How to mount |
|---|---|
| **Flask** | `DispatcherMiddleware` or replace `app.wsgi_app` |
| **Django** (classic WSGI) | Mount as sub-application in `urls.py` |
| **Falcon** | `app.add_sink(WsgiSoapApp(soap_app), "/soap")` |
| **Bottle** | `app.mount("/soap", WsgiSoapApp(soap_app))` |
| **Pyramid** | Composable WSGI stack |

WSGI servers (Gunicorn, uWSGI, mod_wsgi) can run `WsgiSoapApp` directly.

**Flask example:**

```python
from flask import Flask
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from soapbar.server.application import SoapApplication
from soapbar.server.wsgi import WsgiSoapApp

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
from soapbar.core.wsdl.parser import parse_wsdl, parse_wsdl_file

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
from soapbar.client.client import SoapClient
from soapbar.core.fault import SoapFault

# From a live WSDL URL (fetches WSDL over HTTP)
client = SoapClient(wsdl_url="http://localhost:8000/soap?wsdl")

# From a WSDL string/bytes you already have
client = SoapClient.from_wsdl_string(wsdl_bytes)

# From a WSDL file
client = SoapClient.from_file("service.wsdl")

# Manual — no WSDL, specify endpoint and style directly
from soapbar.core.binding import BindingStyle
from soapbar.core.envelope import SoapVersion

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

---

## XSD type system

soapbar includes a registry of 27 built-in XSD types. Types handle serialization to and from XML text.

```python
from soapbar.core.types import xsd

# Resolve a type by XSD name
int_type = xsd.resolve("int")        # XsdType for xsd:int
str_type = xsd.resolve("string")     # XsdType for xsd:string

# Map a Python type to its XSD equivalent
xsd_type = xsd.python_to_xsd(int)    # -> xsd:int XsdType
xsd_type = xsd.python_to_xsd(str)    # -> xsd:string XsdType

# Serialize / deserialize
int_type.to_xml(42)       # "42"
int_type.from_xml("42")   # 42
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

```python
from soapbar.core.fault import SoapFault

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

# Parse a fault from a response
from soapbar.core.envelope import SoapEnvelope

envelope = SoapEnvelope.from_xml(response_bytes)
if envelope.is_fault:
    fault = envelope.fault   # SoapFault instance
    raise fault
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

## License

MIT with Attribution
