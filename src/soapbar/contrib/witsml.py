# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Typed client for the WITSML 1.4.1.1 STORE API (oil & gas).

WITSML (Wellsite Information Transfer Standard Markup Language) is an Energistics
standard for upstream drilling data. Its STORE interface is a classic
SOAP **RPC** service whose WSDL declares no ``<types>`` — all domain data rides
as an XML *string* inside the operation parameters. This client registers the
STORE operations manually (soapbar's RPC binding) and adds:

* an :func:`options_in` builder for the ``OptionsIn`` string,
* return-code handling — a positive ``Result`` is success, a negative one raises
  :class:`WitsmlError` (whose text is resolved via ``WMLS_GetBaseMsg``).

Domain XML is passed through as strings (build/parse it with the soapbar core
or your own models); this client owns the protocol, not the data model.

    from soapbar.contrib.witsml import WitsmlClient, options_in

    with WitsmlClient("https://host/store", "user", "pass") as wits:
        xml = wits.get_from_store("well", "<wells/>", options=options_in(returnElements="id-only"))

Confirm whether your server speaks RPC/Encoded (the 1.4.1.1 default) or
RPC/Literal and pass ``binding`` accordingly. Requires httpx (``soapbar[witsml]``).
"""
from __future__ import annotations

from typing import Any

from soapbar.client.client import SoapClient
from soapbar.client.transport import HttpTransport
from soapbar.core.binding import BindingStyle, OperationParameter, OperationSignature
from soapbar.core.exceptions import SoapbarError
from soapbar.core.types import xsd
from soapbar.core.wssecurity import UsernameTokenCredential

#: WITSML 1.4.1.1 message namespace (the RPC wrapper element namespace).
STORE_NS = "http://www.witsml.org/message/120"
#: SOAPAction prefix; the full action is ``…/Store.<Operation>``.
ACTION_BASE = "http://www.witsml.org/action/120/Store."


class WitsmlError(SoapbarError):
    """Base class for WITSML STORE errors, carrying the WITSML result ``code``.

    ``code`` is the numeric WITSML result: a negative value is a server-reported
    error (see :class:`WitsmlServerError`), and ``0`` is used here for a
    protocol-level problem such as a response missing its ``Result`` element.
    """

    def __init__(self, code: int, message: str = "") -> None:
        self.code = code
        self.message = message
        super().__init__(f"WITSML error {code}" + (f": {message}" if message else ""))


class WitsmlServerError(WitsmlError):
    """The STORE server returned a negative WITSML result code (a real
    server-side failure, as opposed to a malformed/missing response envelope,
    which stays a plain :class:`WitsmlError`)."""


def options_in(**options: Any) -> str:
    """Build a WITSML ``OptionsIn`` string from keyword pairs.

    ``options_in(returnElements="all", maxReturnNodes=10)`` →
    ``"returnElements=all;maxReturnNodes=10"``.
    """
    return ";".join(f"{key}={value}" for key, value in options.items())


def _param(name: str, xsd_name: str) -> OperationParameter:
    xsd_type = xsd.resolve(xsd_name)
    assert xsd_type is not None  # noqa: S101 - "string"/"int" are always registered
    return OperationParameter(name, xsd_type)


def _str(name: str) -> OperationParameter:
    return _param(name, "string")


def _int(name: str) -> OperationParameter:
    return _param(name, "int")


def _field(resp: Any, name: str) -> Any:
    if isinstance(resp, dict):
        return resp.get(name)
    return getattr(resp, name, None)


class WitsmlClient:
    """A typed wrapper over the WITSML 1.4.1.1 STORE operations."""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        *,
        binding: BindingStyle = BindingStyle.RPC_ENCODED,
        transport: HttpTransport | None = None,
    ) -> None:
        cred = UsernameTokenCredential(username=username, password=password)
        self._client = SoapClient.manual(
            address=url,
            binding_style=binding,
            wss_credential=cred,
            transport=transport,
        )
        for sig in self._signatures():
            self._client.register_operation(sig)

    @staticmethod
    def _op(
        name: str,
        inputs: list[OperationParameter],
        outputs: list[OperationParameter],
    ) -> OperationSignature:
        return OperationSignature(
            name=name,
            input_params=inputs,
            output_params=outputs,
            soap_action=ACTION_BASE + name,
            input_namespace=STORE_NS,
            output_namespace=STORE_NS,
        )

    @classmethod
    def _signatures(cls) -> list[OperationSignature]:
        return [
            cls._op("WMLS_GetCap", [_str("OptionsIn")],
                    [_str("CapabilitiesOut"), _str("SuppMsgOut"), _int("Result")]),
            cls._op("WMLS_GetFromStore",
                    [_str("WMLtypeIn"), _str("QueryIn"), _str("OptionsIn"), _str("CapabilitiesIn")],
                    [_str("XMLout"), _str("SuppMsgOut"), _int("Result")]),
            cls._op("WMLS_AddToStore",
                    [_str("WMLtypeIn"), _str("XMLin"), _str("OptionsIn"), _str("CapabilitiesIn")],
                    [_str("SuppMsgOut"), _int("Result")]),
            cls._op("WMLS_UpdateInStore",
                    [_str("WMLtypeIn"), _str("XMLin"), _str("OptionsIn"), _str("CapabilitiesIn")],
                    [_str("SuppMsgOut"), _int("Result")]),
            cls._op("WMLS_DeleteFromStore",
                    [_str("WMLtypeIn"), _str("QueryIn"), _str("OptionsIn"), _str("CapabilitiesIn")],
                    [_str("SuppMsgOut"), _int("Result")]),
            cls._op("WMLS_GetVersion", [], [_str("Result")]),
            cls._op("WMLS_GetBaseMsg", [_int("ReturnValueIn")], [_str("Result")]),
        ]

    # -- low-level result handling -----------------------------------------
    @staticmethod
    def _result_code(resp: Any) -> int | None:
        value = _field(resp, "Result")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _check(self, resp: Any) -> int:
        """Return the result code, raising on a negative or missing value."""
        code = self._result_code(resp)
        if code is None:
            raise WitsmlError(0, "no Result code in WITSML response")
        if code < 0:
            raise WitsmlServerError(code, self._safe_base_message(code))
        return code

    def _safe_base_message(self, code: int) -> str:
        try:
            return self.get_base_message(code)
        except Exception:
            # Best-effort text lookup; never let it mask the real error.
            return ""

    # -- operations --------------------------------------------------------
    def get_version(self) -> str:
        """Return the server's supported data-schema versions (WMLS_GetVersion)."""
        # Single-output operation: soapbar returns the scalar Result directly.
        return str(self._client.call("WMLS_GetVersion") or "")

    def get_base_message(self, code: int) -> str:
        """Resolve the human-readable text for a WITSML return code."""
        return str(self._client.call("WMLS_GetBaseMsg", ReturnValueIn=code) or "")

    def get_cap(self, options: str = "dataVersion=1.4.1.1") -> str:
        """Return the server capabilities document (WMLS_GetCap)."""
        resp = self._client.call("WMLS_GetCap", OptionsIn=options)
        self._check(resp)
        return str(_field(resp, "CapabilitiesOut") or "")

    def get_from_store(
        self, wml_type: str, query_xml: str, *, options: str = "", capabilities: str = ""
    ) -> str:
        """Query the store and return the matching WITSML XML (WMLS_GetFromStore)."""
        resp = self._client.call(
            "WMLS_GetFromStore",
            WMLtypeIn=wml_type, QueryIn=query_xml,
            OptionsIn=options, CapabilitiesIn=capabilities,
        )
        self._check(resp)
        return str(_field(resp, "XMLout") or "")

    def add_to_store(
        self, wml_type: str, xml_in: str, *, options: str = "", capabilities: str = ""
    ) -> int:
        """Add an object to the store (WMLS_AddToStore); returns the result code."""
        resp = self._client.call(
            "WMLS_AddToStore",
            WMLtypeIn=wml_type, XMLin=xml_in,
            OptionsIn=options, CapabilitiesIn=capabilities,
        )
        return self._check(resp)

    def update_in_store(
        self, wml_type: str, xml_in: str, *, options: str = "", capabilities: str = ""
    ) -> int:
        """Update an object in the store (WMLS_UpdateInStore); returns the result code."""
        resp = self._client.call(
            "WMLS_UpdateInStore",
            WMLtypeIn=wml_type, XMLin=xml_in,
            OptionsIn=options, CapabilitiesIn=capabilities,
        )
        return self._check(resp)

    def delete_from_store(
        self, wml_type: str, query_xml: str, *, options: str = "", capabilities: str = ""
    ) -> int:
        """Delete an object from the store (WMLS_DeleteFromStore); returns the result code."""
        resp = self._client.call(
            "WMLS_DeleteFromStore",
            WMLtypeIn=wml_type, QueryIn=query_xml,
            OptionsIn=options, CapabilitiesIn=capabilities,
        )
        return self._check(resp)

    def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> WitsmlClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
