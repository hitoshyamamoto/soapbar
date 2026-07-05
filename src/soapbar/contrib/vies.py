# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Typed client for the EU VIES VAT-number validation service.

VIES (VAT Information Exchange System) confirms whether an EU VAT number is
valid for intra-Community supply. See Council Regulation (EC) No. 904/2010,
Art. 31. The service WSDL is bundled with soapbar, so constructing a client
needs no network access; only the actual call reaches the EC endpoint.

    from soapbar.contrib.vies import ViesClient

    vies = ViesClient()
    result = vies.check_vat("BE", "0203201340")
    if result.valid:
        print(result.name, result.address)

Usage restriction (stated in the WSDL itself): VIES is for confirming
individual VAT numbers. Bulk extraction / retransmission is forbidden.

Requires httpx (``soapbar[vies]``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from typing import Any

from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport
from soapbar.core.exceptions import SoapbarError
from soapbar.core.fault import SoapFault

__all__ = [
    "VIES_ENDPOINT",
    "MatchCode",
    "ViesApproxResult",
    "ViesClient",
    "ViesError",
    "ViesInputError",
    "ViesRateLimitError",
    "ViesResult",
    "ViesUnavailableError",
]

#: Live VIES SOAP endpoint (HTTPS; the bundled WSDL lists the legacy HTTP URL).
VIES_ENDPOINT = "https://ec.europa.eu/taxation_customs/vies/services/checkVatService"

# Input shapes the EC service documents (and rejects with INVALID_INPUT otherwise).
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_VAT_RE = re.compile(r"^[0-9A-Za-z+*.]{2,12}$")

# Fault strings the service returns, grouped by how a caller should react.
_INPUT_FAULTS = {"INVALID_INPUT", "INVALID_REQUESTER_INFO"}
_RATE_LIMIT_FAULTS = {"GLOBAL_MAX_CONCURRENT_REQ", "MS_MAX_CONCURRENT_REQ"}
_UNAVAILABLE_FAULTS = {"SERVICE_UNAVAILABLE", "MS_UNAVAILABLE", "TIMEOUT"}


class ViesError(SoapbarError):
    """Base class for VIES-specific errors."""


class ViesInputError(ViesError):
    """The country code or VAT number was malformed / rejected (INVALID_INPUT)."""


class ViesRateLimitError(ViesError):
    """The service is rate-limiting requests; retry later."""


class ViesUnavailableError(ViesError):
    """VIES or the member-state node is temporarily unavailable; retry later."""


@dataclass(frozen=True)
class ViesResult:
    """Outcome of a ``check_vat`` call."""

    country_code: str
    vat_number: str
    valid: bool
    request_date: str | None = None
    name: str | None = None
    address: str | None = None


class MatchCode(str, Enum):
    """Per-field match outcome from ``checkVatApprox``."""

    VALID = "1"
    INVALID = "2"
    NOT_PROCESSED = "3"


@dataclass(frozen=True)
class ViesApproxResult:
    """Outcome of a ``check_vat_approx`` call.

    Carries ``request_identifier`` — the proof-of-consultation token businesses
    keep for audit — plus per-field match codes for the trader details supplied.
    """

    country_code: str
    vat_number: str
    valid: bool
    request_identifier: str | None = None
    request_date: str | None = None
    trader_name: str | None = None
    trader_address: str | None = None
    name_match: MatchCode | None = None
    company_type_match: MatchCode | None = None
    street_match: MatchCode | None = None
    postcode_match: MatchCode | None = None
    city_match: MatchCode | None = None


def _match(value: Any) -> MatchCode | None:
    if value in (None, ""):
        return None
    try:
        return MatchCode(str(value))
    except ValueError:
        return None


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


class ViesClient:
    """A typed wrapper over the VIES ``checkVat`` operation.

    The WSDL is loaded from the copy bundled with soapbar (no network at
    construction); pass a custom :class:`HttpTransport` to control timeouts or
    proxies, or *endpoint* to target a mirror.
    """

    def __init__(
        self,
        *,
        transport: HttpTransport | None = None,
        endpoint: str = VIES_ENDPOINT,
    ) -> None:
        wsdl = resources.files("soapbar.contrib").joinpath("_wsdl/checkVatService.wsdl")
        with resources.as_file(wsdl) as path:
            # endpoint overrides the WSDL's legacy HTTP URL with HTTPS.
            self._client = SoapClient.from_file(str(path), transport=transport, endpoint=endpoint)

    def check_vat(self, country_code: str, vat_number: str) -> ViesResult:
        """Validate a single VAT number.

        Args:
            country_code: Two-letter ISO country code (e.g. ``"BE"``).
            vat_number: The VAT number without the country prefix.

        Raises:
            ViesInputError: The input is malformed or the service rejects it.
            ViesRateLimitError: The service is throttling; retry later.
            ViesUnavailableError: VIES / the member state is down; retry later.
            ViesError: Any other VIES-side fault.
        """
        country_code = country_code.strip().upper()
        vat_number = vat_number.strip().replace(" ", "")
        if not _COUNTRY_RE.match(country_code):
            raise ViesInputError(f"invalid country code: {country_code!r}")
        if not _VAT_RE.match(vat_number):
            raise ViesInputError(f"invalid VAT number: {vat_number!r}")

        try:
            resp = self._client.call(
                "checkVat", countryCode=country_code, vatNumber=vat_number
            )
        except SoapFault as fault:
            raise self._map_fault(fault) from fault

        return ViesResult(
            country_code=_field(resp, "countryCode") or country_code,
            vat_number=_field(resp, "vatNumber") or vat_number,
            valid=bool(_field(resp, "valid")),
            request_date=_field(resp, "requestDate"),
            name=_field(resp, "name"),
            address=_field(resp, "address"),
        )

    def check_vat_approx(
        self,
        country_code: str,
        vat_number: str,
        *,
        trader_name: str | None = None,
        trader_company_type: str | None = None,
        trader_street: str | None = None,
        trader_postcode: str | None = None,
        trader_city: str | None = None,
        requester_country_code: str | None = None,
        requester_vat_number: str | None = None,
    ) -> ViesApproxResult:
        """Validate a VAT number and (optionally) match trader details.

        Returns a :class:`ViesApproxResult` including ``request_identifier`` —
        the proof-of-consultation token — and per-field match codes. Supply any
        ``trader_*`` fields you want matched; omit the rest. Providing
        ``requester_*`` (your own VAT) yields a consultation identifier.

        Raises the same typed exceptions as :meth:`check_vat`.
        """
        country_code = country_code.strip().upper()
        vat_number = vat_number.strip().replace(" ", "")
        if not _COUNTRY_RE.match(country_code):
            raise ViesInputError(f"invalid country code: {country_code!r}")
        if not _VAT_RE.match(vat_number):
            raise ViesInputError(f"invalid VAT number: {vat_number!r}")

        # Only send the optional fields the caller supplied (they are minOccurs=0).
        optional = {
            "traderName": trader_name,
            "traderCompanyType": trader_company_type,
            "traderStreet": trader_street,
            "traderPostcode": trader_postcode,
            "traderCity": trader_city,
            "requesterCountryCode": requester_country_code,
            "requesterVatNumber": requester_vat_number,
        }
        kwargs = {k: v for k, v in optional.items() if v is not None}

        try:
            resp = self._client.call(
                "checkVatApprox", countryCode=country_code, vatNumber=vat_number, **kwargs
            )
        except SoapFault as fault:
            raise self._map_fault(fault) from fault

        return ViesApproxResult(
            country_code=_field(resp, "countryCode") or country_code,
            vat_number=_field(resp, "vatNumber") or vat_number,
            valid=bool(_field(resp, "valid")),
            request_identifier=_field(resp, "requestIdentifier"),
            request_date=_field(resp, "requestDate"),
            trader_name=_field(resp, "traderName"),
            trader_address=_field(resp, "traderAddress"),
            name_match=_match(_field(resp, "traderNameMatch")),
            company_type_match=_match(_field(resp, "traderCompanyTypeMatch")),
            street_match=_match(_field(resp, "traderStreetMatch")),
            postcode_match=_match(_field(resp, "traderPostcodeMatch")),
            city_match=_match(_field(resp, "traderCityMatch")),
        )

    @staticmethod
    def _map_fault(fault: SoapFault) -> ViesError:
        code = (fault.faultstring or "").strip().upper()
        if code in _INPUT_FAULTS:
            return ViesInputError(code)
        if code in _RATE_LIMIT_FAULTS:
            return ViesRateLimitError(code)
        if code in _UNAVAILABLE_FAULTS:
            return ViesUnavailableError(code)
        return ViesError(fault.faultstring or fault.faultcode or "unknown VIES fault")

    def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> ViesClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
