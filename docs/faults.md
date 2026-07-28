# Faults and one-way operations

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

# SOAP 1.2 subcodes — each is (namespace_uri, localname) for spec-compliant QName
fault_12 = SoapFault(
    faultcode="Client",
    faultstring="Validation error",
    subcodes=[("http://example.com/errors", "InvalidQuantity")],
)
```

Fault code translation is automatic:

| Canonical (used in soapbar) | SOAP 1.1 wire | SOAP 1.2 wire |
|---|---|---|
| `Client` | `Client` | `Sender` |
| `Server` | `Server` | `Receiver` |

---

## One-way operations

One-way operations fire-and-forget: the server processes the message and returns HTTP 202 Accepted with an empty body (SOAP 1.2 Part 2 §7.5.1).

```python
from soapbar import SoapService, soap_operation


class EventService(SoapService):
    __service_name__ = "EventService"
    __tns__ = "http://example.com/events"

    @soap_operation(one_way=True)
    def publish_event(self, event_type: str, payload: str) -> None:
        # Process asynchronously — no response is sent
        _event_queue.put((event_type, payload))
```

The client receives `202 Accepted` with no body. `SoapClient.call()` returns `None` for one-way operations.
