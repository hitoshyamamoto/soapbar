# Quick start

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
