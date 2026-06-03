"""
examples/18_witsml/witsml_demo.py — Consume a WITSML 1.4.1.1 STORE server with soapbar.

READY CLIENT
    For real use, prefer the typed `soapbar.contrib.witsml.WitsmlClient`
    (`soapbar[witsml]`) — it registers the STORE operations, builds `OptionsIn`,
    and maps return codes to errors. This script shows the raw mechanics it wraps.

WHAT THIS DEMONSTRATES
    soapbar's headline differentiator: the RPC binding (RPC/Encoded or
    RPC/Literal) that zeep/spyne/fastapi-soap do not fully cover, driving the
    WITSML STORE API used across the upstream oil & gas industry. Because the
    WITSML WSDL declares no <types> (it uses only W3C primitive types and carries
    all domain data as an XML *string* inside the parameters), this example uses
    soapbar's MANUAL operation registration rather than WSDL-driven typing.

SERVICE FACTS (verified against the Energistics WITSML STORE API v1.4.1 spec,
the WMLS.WSDL, and the PDS reference implementation IWitsmlStore.cs)
    Binding        : RPC, commonly Encoded for 1.4.1.1 (confirm per server)
    SOAP action    : http://www.witsml.org/action/120/Store.<Operation>
    Wrapper ns     : http://www.witsml.org/message/120
    No <types>     : domain XML travels as a string in XMLin / QueryIn / XMLout
    Operations and parameter order:
        WMLS_GetCap(OptionsIn)                                   -> CapabilitiesOut, SuppMsgOut, Result
        WMLS_GetFromStore(WMLtypeIn, QueryIn, OptionsIn, CapabilitiesIn)
                                                                 -> XMLout, SuppMsgOut, Result
        WMLS_AddToStore(WMLtypeIn, XMLin, OptionsIn, CapabilitiesIn)
                                                                 -> SuppMsgOut, Result
        WMLS_UpdateInStore(WMLtypeIn, XMLin, OptionsIn, CapabilitiesIn) -> SuppMsgOut, Result
        WMLS_DeleteFromStore(WMLtypeIn, QueryIn, OptionsIn, CapabilitiesIn) -> SuppMsgOut, Result
        WMLS_GetVersion()                                        -> Result (version string)
        WMLS_GetBaseMsg(ReturnValueIn)                           -> Result (message text)
    OptionsIn      : semicolon-delimited key=value, e.g. "returnElements=all"
    CapabilitiesIn : client capabilities object (capClient); per spec required for
                     GetFromStore, though many servers tolerate "" (empty string).
    Return code    : positive => success, negative => error (resolve text via
                     WMLS_GetBaseMsg).

LICENSING
    Energistics materials are freely available under the Energistics Product
    Licensing Agreement (no fees); acknowledge Energistics as the source.

REQUIREMENTS
    Works with the current soapbar release: manual operation registration
    (OperationSignature / register_operation), RPC binding, and WS-Security
    UsernameToken are all already implemented.
    Needs a reachable WITSML 1.4.1.1 server (e.g. an open-source reference/
    simulator server) and credentials.

Run:
    uv run python examples/18_witsml/witsml_demo.py

NOTE
    Confirm whether your target server uses RPC_ENCODED or RPC_LITERAL and switch
    BINDING below accordingly. Confirm the exact keyword soapbar's manual client
    expects to attach a WS-Security credential (shown here as `wss_credential=`,
    matching the documented SoapClient.manual signature).
"""

from __future__ import annotations

from soapbar import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    SoapClient,
    SoapFault,
    xsd,
)
from soapbar.core.wssecurity import UsernameTokenCredential

# --- server configuration (edit these) -------------------------------------
WITSML_URL = "https://example-witsml-server/witsml/services/store"  # replace
WITSML_USER = "demo"
WITSML_PASSWORD = "demo"
BINDING = BindingStyle.RPC_ENCODED  # switch to RPC_LITERAL if your server uses it
SOAP_ACTION_BASE = "http://www.witsml.org/action/120/Store."


def _string(name: str) -> OperationParameter:
    return OperationParameter(name, xsd.resolve("string"))


def _int(name: str) -> OperationParameter:
    return OperationParameter(name, xsd.resolve("int"))


def build_client() -> SoapClient:
    """Build a manual RPC client with WS-Security UsernameToken and register
    the WITSML STORE operations (the WSDL has no <types>, so we declare the
    signatures ourselves)."""
    cred = UsernameTokenCredential(username=WITSML_USER, password=WITSML_PASSWORD)
    client = SoapClient.manual(
        address=WITSML_URL,
        binding_style=BINDING,
        wss_credential=cred,
    )

    # WMLS_GetCap(OptionsIn) -> CapabilitiesOut, SuppMsgOut, Result
    client.register_operation(
        OperationSignature(
            name="WMLS_GetCap",
            input_params=[_string("OptionsIn")],
            output_params=[
                _string("CapabilitiesOut"),
                _string("SuppMsgOut"),
                _int("Result"),
            ],
        )
    )

    # WMLS_GetFromStore(WMLtypeIn, QueryIn, OptionsIn, CapabilitiesIn)
    #   -> XMLout, SuppMsgOut, Result
    client.register_operation(
        OperationSignature(
            name="WMLS_GetFromStore",
            input_params=[
                _string("WMLtypeIn"),
                _string("QueryIn"),
                _string("OptionsIn"),
                _string("CapabilitiesIn"),
            ],
            output_params=[
                _string("XMLout"),
                _string("SuppMsgOut"),
                _int("Result"),
            ],
        )
    )

    # WMLS_AddToStore(WMLtypeIn, XMLin, OptionsIn, CapabilitiesIn) -> SuppMsgOut, Result
    client.register_operation(
        OperationSignature(
            name="WMLS_AddToStore",
            input_params=[
                _string("WMLtypeIn"),
                _string("XMLin"),
                _string("OptionsIn"),
                _string("CapabilitiesIn"),
            ],
            output_params=[_string("SuppMsgOut"), _int("Result")],
        )
    )

    # WMLS_DeleteFromStore(WMLtypeIn, QueryIn, OptionsIn, CapabilitiesIn) -> SuppMsgOut, Result
    client.register_operation(
        OperationSignature(
            name="WMLS_DeleteFromStore",
            input_params=[
                _string("WMLtypeIn"),
                _string("QueryIn"),
                _string("OptionsIn"),
                _string("CapabilitiesIn"),
            ],
            output_params=[_string("SuppMsgOut"), _int("Result")],
        )
    )

    # WMLS_GetBaseMsg(ReturnValueIn) -> Result (human-readable message text)
    client.register_operation(
        OperationSignature(
            name="WMLS_GetBaseMsg",
            input_params=[_int("ReturnValueIn")],
            output_params=[_string("Result")],
        )
    )

    return client


# A minimal WITSML 1.4.1.1 query for the list of wells (returnElements controls
# how much each well carries back). The domain XML is a plain string.
WELL_QUERY = (
    '<wells xmlns="http://www.witsml.org/schemas/1series" version="1.4.1.1">'
    "  <well/>"
    "</wells>"
)


def _field(obj, name):
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _result_code(obj):
    val = _field(obj, "Result")
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def main() -> None:
    client = build_client()

    try:
        # 1) Ask the server what it supports.
        cap = client.call("WMLS_GetCap", OptionsIn="dataVersion=1.4.1.1")
        print("GetCap Result code:", _result_code(cap))

        # 2) Read the list of wells. CapabilitiesIn left empty (server-tolerant);
        #    pass a real capClient string if your server requires it.
        resp = client.call(
            "WMLS_GetFromStore",
            WMLtypeIn="well",
            QueryIn=WELL_QUERY,
            OptionsIn="returnElements=id-only",
            CapabilitiesIn="",
        )
        code = _result_code(resp)
        print("GetFromStore Result code:", code)
        if code is not None and code < 0:
            # Negative codes are errors; resolve the human-readable text.
            base = client.call("WMLS_GetBaseMsg", ReturnValueIn=code)
            print("  Server error message:", _field(base, "Result"))
            return
        print("  Returned WITSML XML (truncated):", str(_field(resp, "XMLout"))[:300])

    except SoapFault as fault:
        print(f"SOAP fault: {fault.faultcode} / {fault.faultstring}")


if __name__ == "__main__":
    main()
