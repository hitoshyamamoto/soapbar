# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""The public exception hierarchy is rooted at SoapbarError.

Every error soapbar raises deliberately — core faults, security/validation
failures, the size-limit breach, and the contrib-client errors — must be
catchable as `SoapbarError`, while keeping its existing, more specific base
(e.g. `BodyTooLargeError` stays a `ValueError`) and its own typed sub-hierarchy.
"""
from __future__ import annotations

import pytest

from soapbar import SoapbarError, SoapFault
from soapbar.core.wssecurity import SecurityValidationError, XmlSecurityError
from soapbar.core.xml import BodyTooLargeError

# Core error types all root at SoapbarError.
CORE_ERRORS = [SoapFault, XmlSecurityError, SecurityValidationError, BodyTooLargeError]


@pytest.mark.parametrize("cls", CORE_ERRORS)
def test_core_errors_are_soapbar_errors(cls: type[Exception]) -> None:
    assert issubclass(cls, SoapbarError)


def test_soapbar_error_is_plain_exception() -> None:
    # Root is a bare Exception subclass — nothing exotic in the MRO.
    assert SoapbarError.__mro__ == (SoapbarError, Exception, BaseException, object)


def test_body_too_large_keeps_value_error_compat() -> None:
    # Dual base: catchable as SoapbarError AND as ValueError (back-compat for
    # existing `except (ValueError, TypeError)` ingress handlers).
    assert issubclass(BodyTooLargeError, SoapbarError)
    assert issubclass(BodyTooLargeError, ValueError)
    err = BodyTooLargeError("too big")
    assert isinstance(err, SoapbarError)
    assert isinstance(err, ValueError)


def test_soap_fault_is_catchable_as_soapbar_error() -> None:
    with pytest.raises(SoapbarError):
        raise SoapFault("Client", "bad request")


def test_contrib_errors_root_at_soapbar_error_and_keep_subhierarchy() -> None:
    # Imported lazily so the core-only test file needs no contrib extras to run
    # the core assertions above; these imports themselves have no heavy deps.
    from soapbar.contrib.ana import AnaError, AnaServiceError
    from soapbar.contrib.nfe import NfeError, NfeInputError
    from soapbar.contrib.vies import ViesError, ViesInputError
    from soapbar.contrib.witsml import WitsmlError, WitsmlServerError

    # Every contrib base roots at SoapbarError...
    for base in (NfeError, AnaError, WitsmlError, ViesError):
        assert issubclass(base, SoapbarError)

    # ...and each keeps a typed sub-hierarchy under its own base.
    assert issubclass(NfeInputError, NfeError)
    assert issubclass(AnaServiceError, AnaError)
    assert issubclass(WitsmlServerError, WitsmlError)
    assert issubclass(ViesInputError, ViesError)


def test_single_except_soapbar_error_catches_every_contrib_error() -> None:
    from soapbar.contrib.ana import AnaServiceError
    from soapbar.contrib.nfe import NfeInputError
    from soapbar.contrib.vies import ViesRateLimitError
    from soapbar.contrib.witsml import WitsmlServerError

    for exc in (
        NfeInputError("bad cUF"),
        AnaServiceError("no data"),
        WitsmlServerError(-433, "base not found"),
        ViesRateLimitError("MS_MAX_CONCURRENT_REQ"),
    ):
        with pytest.raises(SoapbarError):
            raise exc


def test_witsml_server_error_carries_code() -> None:
    from soapbar.contrib.witsml import WitsmlError, WitsmlServerError

    err = WitsmlServerError(-433, "base not found")
    assert err.code == -433
    assert err.message == "base not found"
    assert isinstance(err, WitsmlError)
