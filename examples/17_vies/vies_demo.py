"""
examples/17_vies/vies_demo.py — Consume the EU VIES VAT-validation SOAP service with soapbar.

READY CLIENT
    For real use, prefer the typed `soapbar.contrib.vies.ViesClient`
    (`soapbar[vies]`) — it adds input validation, typed faults, and a bundled
    WSDL. This script shows the raw mechanics that client wraps.

WHAT THIS DEMONSTRATES
    Pointing soapbar's WSDL-driven client at a real, public government SOAP
    service and getting a typed result back — with no authentication and no
    client certificate. VIES is the simplest real-world smoke test for the
    framework, and the closest competitor to the common `zeep`-based approach.

SERVICE FACTS (verified against the official EC WSDL)
    WSDL      : https://ec.europa.eu/taxation_customs/vies/checkVatService.wsdl
    Binding   : document / literal, SOAP 1.1, transport HTTP, soapAction=""
    Namespace : urn:ec.europa.eu:taxud:vies:services:checkVat
    Operation : checkVat(countryCode, vatNumber)
                -> (countryCode, vatNumber, requestDate, valid, name?, address?)
    Input     : countryCode matches [A-Z]{2}; vatNumber matches [0-9A-Za-z\\+\\*\\.]{2,12}
    Faults    : INVALID_INPUT, GLOBAL_MAX_CONCURRENT_REQ, MS_MAX_CONCURRENT_REQ,
                SERVICE_UNAVAILABLE, MS_UNAVAILABLE, TIMEOUT
    Legal     : Council Regulation (EC) No. 904/2010, Art. 31.

USAGE RESTRICTION (stated in the WSDL itself)
    VIES is for confirming individual VAT numbers for intra-Community supply.
    Bulk extraction / retransmission is forbidden. This demo issues single calls.

REQUIREMENTS
    Works with the current soapbar release (WSDL-driven client, no extras needed).
    Network access to ec.europa.eu.

Run:
    uv run python examples/17_vies/vies_demo.py

NOTE
    The exact shape of the response object returned by soapbar's WSDL-driven
    client should be confirmed against the installed version; this example reads
    the documented response fields and falls back to attribute/dict access.
"""

from __future__ import annotations

from soapbar import SoapClient, SoapFault

VIES_WSDL = "https://ec.europa.eu/taxation_customs/vies/checkVatService.wsdl"

# Fault strings the EC service returns, grouped by how a caller should treat them.
_INPUT_FAULTS = {"INVALID_INPUT"}
_RATE_LIMIT_FAULTS = {"GLOBAL_MAX_CONCURRENT_REQ", "MS_MAX_CONCURRENT_REQ"}
_UNAVAILABLE_FAULTS = {"SERVICE_UNAVAILABLE", "MS_UNAVAILABLE", "TIMEOUT"}


def _field(obj, name):
    """Read a response field whether soapbar returns an object or a mapping."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def check_vat(country_code: str, vat_number: str):
    """Validate a single EU VAT number. Returns the raw response object.

    Raises SoapFault on a service-side fault; the caller can inspect
    fault.faultstring against the groups above for friendly handling.
    """
    client = SoapClient(wsdl_url=VIES_WSDL)
    # checkVat is document/literal with two string parameters.
    return client.service.checkVat(countryCode=country_code, vatNumber=vat_number)


def main() -> None:
    # A well-known, publicly published valid VAT number is the safest demo input.
    # Replace with any number you have the right to verify.
    country, number = "BE", "0203201340"  # example value; substitute as needed

    try:
        result = check_vat(country, number)
    except SoapFault as fault:
        code = (fault.faultstring or "").strip()
        if code in _INPUT_FAULTS:
            print(f"Invalid input: {country}{number}")
        elif code in _RATE_LIMIT_FAULTS:
            print("VIES is rate-limiting requests; retry later.")
        elif code in _UNAVAILABLE_FAULTS:
            print("VIES (or the member-state node) is temporarily unavailable; retry later.")
        else:
            print(f"Unexpected SOAP fault: {fault.faultcode} / {fault.faultstring}")
        return

    valid = _field(result, "valid")
    print(f"VAT {country}{number} valid? {valid}")
    if valid:
        print("  Name   :", _field(result, "name"))
        print("  Address:", _field(result, "address"))
        print("  Checked:", _field(result, "requestDate"))


if __name__ == "__main__":
    main()
