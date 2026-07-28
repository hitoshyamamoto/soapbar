# WSDL

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

**Remote `wsdl:import` — SSRF guard** — `parse_wsdl` blocks outbound HTTP fetches by default. `wsdl:import` elements whose resolved location starts with `http://` or `https://` raise `ValueError` unless you explicitly opt in:

```python
# Default — safe for untrusted WSDLs; remote imports raise ValueError
defn = parse_wsdl(wsdl_bytes)

# Opt-in — only when the WSDL source is trusted
defn = parse_wsdl(wsdl_bytes, allow_remote_imports=True)
```

This prevents Server-Side Request Forgery (SSRF) when parsing WSDLs from user-supplied URLs or untrusted data. The top-level WSDL fetch (e.g. `SoapClient(wsdl_url=...)`) is always explicit; only `wsdl:import` resolution inside the document is guarded.

---

## WSDL schema validation

`SoapApplication` can validate the SOAP Body of each inbound request against the XSD types embedded in the WSDL. Validation is opt-in and disabled by default.

```python
from soapbar import SoapApplication

soap_app = SoapApplication(
    service_url="https://example.com/soap",
    validate_body_schema=True,   # X07 — WS-I BP 1.1 R2201
)
soap_app.register(MyService())
```

When enabled, the compiled `lxml.etree.XMLSchema` is built once from the WSDL-embedded `<xs:schema>` elements and cached. Any Body element that fails schema validation results in a `Client` fault with the first schema error message. Requests to services with no embedded schemas pass through unchanged.
