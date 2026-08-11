# Comparison with alternatives

| Capability | **soapbar** | zeep | spyne | fastapi-soap |
|---|---|---|---|---|
| SOAP client | ✓ | ✓ | ✗ | ✗ |
| SOAP server | ✓ | ✗ | ✓ | ✓ |
| All 5 binding styles | ✓ | ✓ (client) | ✓ | Partial |
| SOAP 1.1 + 1.2 | ✓ | ✓ | 1.1; 1.2 partial (stub)³ | 1.1 only |
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
| Python versions | 3.10–3.14 | 3.10+² | 3.6–3.10; does not import on 3.12+³ | 3.10+² |

¹ Based on each project's public documentation as of July 2026, not on independent testing — consult each project's documentation for current behaviour.

² zeep and fastapi-soap declare `requires-python >= 3.10` in their current PyPI metadata (accessed 2026-08-10).

³ spyne's PyPI classifiers list Python up to 3.10 and its most recent release is 2.14.0 (2022); it does not import on Python 3.12+ (`ModuleNotFoundError: No module named 'spyne.util.six.moves'`), tracked in [arskom/spyne#700](https://github.com/arskom/spyne/issues/700) and [#711](https://github.com/arskom/spyne/issues/711) (both open, accessed 2026-08-10). Its SOAP 1.2 protocol is described as a stub implementation in the project changelog.

soapbar combines, in a single library, a SOAP client and server, integration with any ASGI or WSGI framework, SOAP 1.1 and 1.2 support, XXE/DoS hardening enabled by default, and an internal conformance suite of 116 tests covering 46 spec-derived checkpoints (see [`tests/audit/test_compliance.py`](https://github.com/hitoshyamamoto/soapbar/blob/main/tests/audit/test_compliance.py)).

## When *not* to use soapbar

Honesty builds trust, so: soapbar is not always the right choice.

- **You only need a SOAP client.** [zeep](https://github.com/mvantellingen/python-zeep) is far more mature and widely deployed — prefer it.
- **You're on Python ≤ 3.10 and spyne already serves you.** There's no urgency to migrate.
- **You need a full NF-e document builder.** soapbar's NF-e client is the SOAP transport + mutual-TLS + signing layer, not a fiscal-document library — pair it with a domain library such as PyNFe or PySIGNFe.
- **You require a 1.0-stable, battle-tested dependency today.** soapbar is Beta (pre-1.0); evaluate the server side for your case.
