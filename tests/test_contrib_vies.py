"""Tests for soapbar.contrib.vies.ViesClient.

Offline tests drive the client with a fake transport that returns canned VIES
envelopes (no network). A single `live` test hits the real EC endpoint and is
deselected by default — run it with `pytest -m live`.
"""
from __future__ import annotations

import pytest

from soapbar.client.transport import HttpTransport
from soapbar.contrib.vies import (
    MatchCode,
    ViesApproxResult,
    ViesClient,
    ViesInputError,
    ViesRateLimitError,
    ViesResult,
    ViesUnavailableError,
)

pytest.importorskip("httpx")

_NS = "urn:ec.europa.eu:taxud:vies:services:checkVat:types"


def _response(valid: bool, *, name: str | None = None, address: str | None = None) -> bytes:
    extra = ""
    if name is not None:
        extra += f"<name>{name}</name>"
    if address is not None:
        extra += f"<address>{address}</address>"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        f'<checkVatResponse xmlns="{_NS}">'
        "<countryCode>BE</countryCode><vatNumber>0203201340</vatNumber>"
        # VIES returns xsd:date *with* a timezone offset — exercises the date fix.
        f"<requestDate>2026-06-02+02:00</requestDate><valid>{str(valid).lower()}</valid>"
        f"{extra}"
        "</checkVatResponse></soap:Body></soap:Envelope>"
    ).encode()


def _fault(faultstring: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        f"<soap:Fault><faultcode>soap:Server</faultcode>"
        f"<faultstring>{faultstring}</faultstring></soap:Fault>"
        "</soap:Body></soap:Envelope>"
    ).encode()


class _FakeTransport(HttpTransport):
    def __init__(self, status: int, body: bytes) -> None:
        super().__init__()
        self._status = status
        self._body = body
        self.sent: tuple[str, bytes, dict[str, str]] | None = None

    def send(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, bytes]:
        self.sent = (url, body, headers)
        return self._status, "text/xml; charset=utf-8", self._body


def _client(status: int = 200, body: bytes | None = None) -> tuple[ViesClient, _FakeTransport]:
    transport = _FakeTransport(status, body if body is not None else _response(True))
    return ViesClient(transport=transport), transport


def test_constructs_offline_from_bundled_wsdl() -> None:
    # No network: the WSDL ships with soapbar and parses at construction.
    ViesClient(transport=_FakeTransport(200, _response(True)))


def test_valid_vat_parses_all_fields() -> None:
    client, transport = _client(body=_response(True, name="ACME NV", address="RUE TEST 1"))
    result = client.check_vat("be", " 0203201340 ")  # normalised before sending
    assert isinstance(result, ViesResult)
    assert result.valid is True
    assert result.country_code == "BE"
    assert result.name == "ACME NV"
    assert result.address == "RUE TEST 1"
    assert result.request_date == "2026-06-02+02:00"
    # The request reached the HTTPS endpoint with the normalised inputs.
    assert transport.sent is not None
    assert transport.sent[0].startswith("https://")
    assert b"0203201340" in transport.sent[1]


def test_request_wrapper_is_namespace_qualified() -> None:
    # The live EU service rejects an unqualified <checkVat>; the wrapper and its
    # children must be in the :types schema namespace (elementFormDefault=qualified).
    client, transport = _client()
    client.check_vat("BE", "0203201340")
    assert transport.sent is not None
    body = transport.sent[1].decode()
    assert _NS in body  # the :types namespace is declared
    assert "<checkVat>" not in body and "<checkVat " not in body  # never unqualified
    # countryCode is qualified too (a prefixed or default-ns child, not bare).
    assert "<countryCode>" not in body


def test_invalid_vat_returns_not_valid() -> None:
    client, _ = _client(body=_response(False))
    result = client.check_vat("BE", "0000000000")
    assert result.valid is False
    assert result.name is None


@pytest.mark.parametrize("cc,vat", [("XYZ", "123"), ("B", "123"), ("BE", "x"), ("BE", "x" * 13)])
def test_input_validation_rejects_bad_args(cc: str, vat: str) -> None:
    client, _ = _client()
    with pytest.raises(ViesInputError):
        client.check_vat(cc, vat)


@pytest.mark.parametrize(
    "faultstring,exc",
    [
        ("INVALID_INPUT", ViesInputError),
        ("MS_MAX_CONCURRENT_REQ", ViesRateLimitError),
        ("SERVICE_UNAVAILABLE", ViesUnavailableError),
        ("MS_UNAVAILABLE", ViesUnavailableError),
    ],
)
def test_fault_mapping(faultstring: str, exc: type[Exception]) -> None:
    client, _ = _client(status=500, body=_fault(faultstring))
    with pytest.raises(exc):
        client.check_vat("BE", "0203201340")


def _approx_response() -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
        f'<checkVatApproxResponse xmlns="{_NS}">'
        "<countryCode>BE</countryCode><vatNumber>0203201340</vatNumber>"
        "<requestDate>2026-06-03+02:00</requestDate><valid>true</valid>"
        "<traderName>ACME NV</traderName><traderAddress>RUE TEST 1</traderAddress>"
        "<traderNameMatch>1</traderNameMatch><traderCityMatch>3</traderCityMatch>"
        "<requestIdentifier>WAPIAAAAX0001</requestIdentifier>"
        "</checkVatApproxResponse></soap:Body></soap:Envelope>"
    ).encode()


def test_check_vat_approx_returns_identifier_and_matches() -> None:
    client, transport = _client(body=_approx_response())
    result = client.check_vat_approx("BE", "0203201340", trader_name="ACME NV")
    assert isinstance(result, ViesApproxResult)
    assert result.valid is True
    assert result.request_identifier == "WAPIAAAAX0001"
    assert result.trader_name == "ACME NV"
    assert result.name_match is MatchCode.VALID
    assert result.city_match is MatchCode.NOT_PROCESSED
    assert result.postcode_match is None  # absent from the response
    # The supplied trader detail is sent, and the request wrapper is qualified.
    # (Unsupplied optionals serialize as empty elements, which VIES tolerates;
    # the minOccurs=0 fix is what lets the call go through without sending them
    # all explicitly.)
    body = transport.sent[1].decode()
    assert "ACME NV" in body
    assert _NS in body


def test_check_vat_approx_validates_input() -> None:
    client, _ = _client(body=_approx_response())
    with pytest.raises(ViesInputError):
        client.check_vat_approx("XYZ", "123")


#: EU VIES deterministic test service — VAT "100" is always VALID, "200" INVALID.
_VIES_TEST_ENDPOINT = (
    "https://ec.europa.eu/taxation_customs/vies/services/checkVatTestService"
)


@pytest.mark.live
def test_live_check_vat() -> None:
    # Hits the EC VIES *test* service (deterministic). Run with: pytest -m live
    with ViesClient(endpoint=_VIES_TEST_ENDPOINT) as client:
        assert client.check_vat("BE", "100").valid is True
        assert client.check_vat("BE", "200").valid is False


@pytest.mark.live
@pytest.mark.parametrize(
    "vat,exc",
    [
        ("201", ViesInputError),       # INVALID_INPUT
        ("300", ViesUnavailableError),  # SERVICE_UNAVAILABLE
        ("301", ViesUnavailableError),  # MS_UNAVAILABLE
        ("302", ViesUnavailableError),  # TIMEOUT
    ],
)
def test_live_fault_map(vat: str, exc: type[Exception]) -> None:
    # The EC test service drives the documented fault spectrum deterministically,
    # so the fault→typed-exception mapping gets real (no-secret) coverage.
    with ViesClient(endpoint=_VIES_TEST_ENDPOINT) as client, pytest.raises(exc):
        client.check_vat("BE", vat)
