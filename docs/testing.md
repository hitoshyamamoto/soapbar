# Testing your SOAP service

You have a `SoapService` and you want tests for it. You do not need a socket, a
server, or a network — `SoapApplication` takes bytes in and returns bytes out,
so the whole request path is callable from a test.

There are two levels, and most suites want both:

| | what it exercises | when to reach for it |
|---|---|---|
| [The fast path](#the-fast-path) | dispatch, serialisation, the HTTP status and body | asserting on the wire format, faults, edge-case envelopes |
| [The round-trip path](#the-round-trip-path) | the above, plus the client's request building and response parsing | asserting on Python values the way a caller sees them |

Every snippet below is runnable as written.

## The service under test

The examples use one small service. It has a fault path, because that is the
half people usually forget to test.

```python
from soapbar import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    SoapApplication,
    SoapClient,
    SoapFault,
    SoapService,
    SoapVersion,
    soap_operation,
    xsd,
)

int_type = xsd.resolve("int")
assert int_type is not None


class Calculator(SoapService):
    __service_name__ = "Calculator"
    __tns__ = "http://example.com/calc"
    __binding_style__ = BindingStyle.DOCUMENT_LITERAL_WRAPPED

    @soap_operation(
        name="Divide",
        input_params=[
            OperationParameter("a", int_type),
            OperationParameter("b", int_type),
        ],
        output_params=[OperationParameter("result", int_type)],
        soap_action="Divide",
    )
    def divide(self, a: int, b: int) -> int:
        if b == 0:
            raise SoapFault("Client", "Cannot divide by zero")
        return a // b


def build_app() -> SoapApplication:
    app = SoapApplication(service_url="https://example.com/soap")
    app.register(Calculator())
    return app
```

## The fast path

[`SoapApplication.handle_request`][handle_request] is the entry point every
framework adapter calls. Hand it an envelope and it returns
`(http_status, content_type, response_body)`.

```python
REQUEST = b"""<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Divide xmlns="http://example.com/calc">
      <a>10</a>
      <b>2</b>
    </Divide>
  </soap:Body>
</soap:Envelope>"""


def test_divide_returns_the_quotient():
    app = build_app()
    status, content_type, body = app.handle_request(REQUEST, soap_action="Divide")

    assert status == 200
    assert "text/xml" in content_type
    assert b"<result>5</result>" in body
```

This is the level to use when the XML itself is the subject: a namespace, an
element name, an encoding, a `Content-Type`. It is also the fastest, since
nothing serialises on the way in.

## The round-trip path

To exercise the client as well, give `SoapClient` a transport that routes into
your application instead of over a socket. Subclass
[`HttpTransport`][HttpTransport] and override `send`:

```python
from soapbar.client.transport import HttpTransport


class InlineTransport(HttpTransport):
    """Routes SoapClient.send() straight into SoapApplication.handle_request()."""

    def __init__(self, app: SoapApplication) -> None:
        super().__init__()
        self._app = app

    def send(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        soap_action = headers.get("SOAPAction", "").strip('"')
        if not soap_action:
            # SOAP 1.2 carries the action inside Content-Type as action="..."
            for part in headers.get("Content-Type", "").split(";"):
                part = part.strip()
                if part.startswith("action="):
                    soap_action = part[len("action=") :].strip('"')
                    break
        return self._app.handle_request(body, soap_action=soap_action)

    async def send_async(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        # call_async() goes through send_async, not send. Override only send
        # and the async path makes a real HTTP request to `url`.
        return self.send(url, body, headers)
```

Then build a client with [`SoapClient.manual`][manual] — no WSDL needed — and
register the operation signature:

```python
DIVIDE = OperationSignature(
    name="Divide",
    input_params=[
        OperationParameter("a", int_type),
        OperationParameter("b", int_type),
    ],
    output_params=[OperationParameter("result", int_type)],
    soap_action="Divide",
)


def make_client(app: SoapApplication) -> SoapClient:
    client = SoapClient.manual(
        "https://example.com/soap",
        binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
        soap_version=SoapVersion.SOAP_11,
        transport=InlineTransport(app),
    )
    client.register_operation(DIVIDE)
    return client


def test_divide_round_trips():
    client = make_client(build_app())

    assert client.call("Divide", a=10, b=2) == 5
    assert client.service.Divide(a=9, b=3) == 3
```

The `binding_style` and `soap_version` on the client must match the service's
`__binding_style__` and `__soap_version__`. They are separate settings on
separate objects, and a mismatch surfaces as a parse failure rather than a
clear message, so it is worth deriving both from one constant in your own
tests.

### Async

`call_async` is the same call through `send_async`:

```python
import asyncio


def test_divide_round_trips_async():
    client = make_client(build_app())
    assert asyncio.run(client.call_async("Divide", a=8, b=4)) == 2
```

### SOAP 1.2

Set the version on both sides. `InlineTransport` above already recovers the
action from `Content-Type`, which is where SOAP 1.2 puts it:

```python
def test_divide_over_soap12():
    class Calc12(Calculator):
        __soap_version__ = SoapVersion.SOAP_12

    app = SoapApplication(service_url="https://example.com/soap")
    app.register(Calc12())

    client = SoapClient.manual(
        "https://example.com/soap",
        binding_style=BindingStyle.DOCUMENT_LITERAL_WRAPPED,
        soap_version=SoapVersion.SOAP_12,
        transport=InlineTransport(app),
    )
    client.register_operation(DIVIDE)

    assert client.call("Divide", a=10, b=5) == 2
```

## Asserting on faults

A `SoapFault` raised in your operation is serialised into a fault envelope by
the application and re-raised as a `SoapFault` by the client. Through the
round-trip path you assert on it as an exception:

```python
import pytest


def test_divide_by_zero_faults():
    client = make_client(build_app())

    with pytest.raises(SoapFault) as excinfo:
        client.call("Divide", a=1, b=0)

    assert excinfo.value.faultcode.endswith("Client")
    assert "divide by zero" in excinfo.value.faultstring
```

Note `endswith` rather than `==`. The faultcode travels as a QName and comes
back namespace-qualified, so an equality assertion on `"Client"` is a test that
passes today and breaks the first time anything about prefixes changes.

Through the fast path you assert on the response instead, which is where you
can also check the HTTP status:

```python
def test_divide_by_zero_returns_500_and_a_fault():
    app = build_app()
    status, _content_type, body = app.handle_request(
        REQUEST.replace(b"<b>2</b>", b"<b>0</b>"), soap_action="Divide"
    )

    assert status == 500
    assert b"Cannot divide by zero" in body
```

Faults raised by your own code keep their `faultstring`. An **unhandled**
exception does not: the server logs it in full and returns
`"An internal error occurred."` to the client, deliberately, so that internals
do not leak. Assert on the scrubbed message, not on the original — and if you
want the original, capture the log. See [Faults and one-way
operations](faults.md).

## A reusable fixture

Paste this into your `conftest.py` and every test gets a wired client:

```python
# conftest.py
import pytest

from soapbar import BindingStyle, SoapApplication, SoapClient, SoapVersion
from soapbar.client.transport import HttpTransport

from myapp.services import Calculator, DIVIDE   # your service and signatures

SERVICE_URL = "https://example.com/soap"
BINDING_STYLE = BindingStyle.DOCUMENT_LITERAL_WRAPPED
SOAP_VERSION = SoapVersion.SOAP_11


class InlineTransport(HttpTransport):
    def __init__(self, app: SoapApplication) -> None:
        super().__init__()
        self._app = app

    def send(self, url, body, headers):
        soap_action = headers.get("SOAPAction", "").strip('"')
        if not soap_action:
            for part in headers.get("Content-Type", "").split(";"):
                part = part.strip()
                if part.startswith("action="):
                    soap_action = part[len("action=") :].strip('"')
                    break
        return self._app.handle_request(body, soap_action=soap_action)

    async def send_async(self, url, body, headers):
        return self.send(url, body, headers)


@pytest.fixture
def app() -> SoapApplication:
    application = SoapApplication(service_url=SERVICE_URL)
    application.register(Calculator())
    return application


@pytest.fixture
def client(app: SoapApplication) -> SoapClient:
    soap_client = SoapClient.manual(
        SERVICE_URL,
        binding_style=BINDING_STYLE,
        soap_version=SOAP_VERSION,
        transport=InlineTransport(app),
    )
    soap_client.register_operation(DIVIDE)
    return soap_client
```

Both fixtures are function-scoped on purpose. `SoapApplication` holds the
registered service instances, so a module-scoped `app` would let one test's
state reach the next.

Tests then read as ordinary Python:

```python
def test_divide(client):
    assert client.call("Divide", a=10, b=2) == 5
```

## Use `https://` in test URLs

`SoapApplication(service_url="http://...")` emits a `UserWarning` about plain
HTTP. Nothing is sent anywhere in these tests — the transport never opens a
socket — but the warning is noise, and a suite run with `-W error` will fail on
it. Use an `https://` URL; it is never dereferenced.

## What this does not cover

Testing through `handle_request` skips whatever your web framework does in
front of it: routing, middleware, authentication, size limits enforced by the
server. Those need the adapter and a test client of the framework's own. See
[Server and frameworks](server.md) for the adapters, and
[Security](security.md) for the limits that are enforced inside soapbar rather
than above it.

[handle_request]: api.md
[HttpTransport]: client.md
[manual]: client.md
