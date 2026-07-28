# Type system and encoding

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

## SOAP array attributes

When using encoded binding styles (`RPC_ENCODED`, `DOCUMENT_ENCODED`), array elements are annotated with the correct version-specific attributes automatically.

SOAP 1.1 (`SOAP-ENC:arrayType`):

```xml
<names soapenc:arrayType="xsd:string[3]"
       xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
  <item>Alice</item><item>Bob</item><item>Carol</item>
</names>
```

SOAP 1.2 (`enc:itemType` + `enc:arraySize`):

```xml
<names enc:itemType="xsd:string" enc:arraySize="3"
       xmlns:enc="http://www.w3.org/2003/05/soap-encoding">
  <item>Alice</item><item>Bob</item><item>Carol</item>
</names>
```

The correct attributes are emitted automatically based on the SOAP version in use — no manual configuration needed. The `get_serializer(style, soap_version)` factory handles the selection.

---

## rpc:result (SOAP 1.2)

SOAP 1.2 Part 2 §4.2.1 defines a `rpc:result` SHOULD convention for naming the return value in RPC responses. soapbar omits it by default (preserving interoperability with zeep and other strict-mode clients) and offers an opt-in:

```python
from soapbar import SoapService, soap_operation


class CalcService(SoapService):
    __service_name__ = "Calc"
    __tns__ = "http://example.com/calc"

    # Default: no rpc:result (interoperable with zeep, WCF, etc.)
    @soap_operation()
    def add(self, a: int, b: int) -> int:
        return a + b

    # Opt-in: emit rpc:result for strict SOAP 1.2 consumers
    @soap_operation(emit_rpc_result=True)
    def add_strict(self, a: int, b: int) -> int:
        return a + b
```

When opted in, the response wrapper contains:

```xml
<CalcResponse>
  <rpc:result xmlns:rpc="http://www.w3.org/2003/05/soap-rpc">return</rpc:result>
  <return>8</return>
</CalcResponse>
```
