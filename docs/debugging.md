# Debugging

The security pages tell you how to keep stack traces *away* from clients;
this page is the other direction — how to see what actually went over the
wire when an integration misbehaves.

## See the envelopes

Three loggers carry the traffic, named after their modules:

| Logger | Emits |
|---|---|
| `soapbar.client.client` | operation dispatch, parsed results |
| `soapbar.client.transport` | request/response envelopes, status, content type |
| `soapbar.server.application` | inbound dispatch on the server side |

```python
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("soapbar.client").setLevel(logging.DEBUG)
```

Envelopes are redacted before they reach a log record — `wsse:Security`
blocks are emptied and password-like elements are blanked wherever they
appear — but redaction is best-effort: treat client `DEBUG` as something you
enable deliberately, for a bounded period, against a log sink you control
(see [Security](security.md#client-debug-logging-and-credentials)).

To inspect an envelope you are *building*, print it directly:

```python
from soapbar.core.envelope import SoapEnvelope, SoapVersion

env = SoapEnvelope(version=SoapVersion.SOAP_11)
print(env.to_string(pretty_print=True))
```

## The failures you will actually hit

**The response is not SOAP at all.** A proxy error page, an auth challenge,
a gateway's JSON error. The client raises `NonSoapResponseError` carrying
the HTTP status, the content type, and a truncated body excerpt — read the
excerpt first; it usually names the real problem (a 407, a redirect to a
login page, a WAF block).

**Namespace off-by-one.** The service faults with "unknown operation" or
ignores your parameters even though the local names look right. Compare the
`xmlns` on your wrapper element against the WSDL's `targetNamespace`
character by character — a trailing slash or an `http`/`https` mismatch is
enough. The DEBUG envelope shows exactly what was sent.

**`SOAPAction` quoting.** Some stacks require the action quoted
(`SOAPAction: "urn:op"`), some unquoted, and some empty-but-present
(`SOAPAction: ""`). soapbar's server indexes both quoted and unquoted forms;
other stacks may not. If a request dispatches in a test tool but not from
code, diff this header first.

**Binding style divergence.** A doc/literal-wrapped client calling an
RPC/literal service (or vice versa) produces bodies that *look* similar and
dispatch nowhere. The client auto-detects style from the WSDL; when there is
no WSDL, make the style explicit and compare against a known-good request
from the service's own documentation.

**Unknown operation on the client.** `call()` raises `ValueError` (naming
the known operations) instead of silently sending an empty wrapper;
`client.service.Tpyo(...)` raises `AttributeError`. If you meant to send an
unregistered, argument-less probe deliberately, pass `allow_unknown=True`.

**Schema validation faults.** With `validate_body_schema=True`, a
`Client` fault beginning `Schema validation failed:` carries the first
schema error verbatim — element form (qualified vs unqualified children) and
lexical type errors are the two usual causes; see
[WSDL schema validation](wsdl.md#wsdl-schema-validation).

## Server-side: seeing errors without leaking them

Unhandled handler exceptions return `"An internal error occurred."` to the
client by design. The full traceback goes to the
`soapbar.server.application` logger — point it at your sink:

```python
logging.getLogger("soapbar.server.application").setLevel(logging.DEBUG)
```

Keep the scrubbing in production; debug with the log, not the fault body.
