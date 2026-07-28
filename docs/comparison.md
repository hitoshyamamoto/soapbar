# Comparison with alternatives

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
| XXE hardened by default | ✓ | not evaluated here¹ | not evaluated here¹ | not evaluated here¹ |
| Message size + depth limits | ✓ | not evaluated here¹ | not evaluated here¹ | not evaluated here¹ |
| WS-Security UsernameToken | ✓ | ✓ (client) | ✓ | ✗ |
| XML Signature / Encryption | ✓ ([security]) | ✗ | Partial | ✗ |
| MTOM/XOP | ✓ | ✓ | ✓ | ✗ |
| WS-Addressing 1.0 | ✓ | ✓ | Partial | ✗ |
| One-way MEP (HTTP 202) | ✓ | ✓ | ✓ | ✗ |
| SOAP array attributes | ✓ | ✓ | ✓ | ✗ |
| Internal conformance suite (116 tests) | ✓ | — | — | — |
| Core dependency | lxml | lxml, requests | lxml | fastapi, lxml |
| Async HTTP client | httpx (optional) | httpx (optional) | — | — |
| Python versions | 3.10–3.14 | 3.8+ | 3.8+ | 3.8+ |

¹ Based on each project's public documentation as of July 2026, not on independent testing — consult each project's documentation for current behaviour.

soapbar combines, in a single library, a SOAP client and server, integration with any ASGI or WSGI framework, SOAP 1.1 and 1.2 support, XXE/DoS hardening enabled by default, and an internal conformance suite of 116 tests covering 46 spec-derived checkpoints (see [`tests/audit/test_compliance.py`](https://github.com/hitoshyamamoto/soapbar/blob/main/tests/audit/test_compliance.py)).
