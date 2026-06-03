"""Tests for soapbar.contrib.witsml.WitsmlClient.

A routing fake transport returns a canned RPC/encoded response per operation
(matched on the wrapper name in the request body), so offline tests cover the
success path, return-code errors, and the WMLS_GetBaseMsg text lookup. No
network. A `live` test (deselected by default) is provided for a real server.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

import pytest

from soapbar.client.transport import HttpTransport
from soapbar.contrib.witsml import WitsmlClient, WitsmlError, options_in

pytest.importorskip("httpx")

_NS = "http://www.witsml.org/message/120"


def _resp(op: str, fields: dict[str, object]) -> bytes:
    # RPC/encoded: prefixed wrapper namespace → unqualified accessor elements.
    body = "".join(
        f'<{k} xsi:type="xsd:{"int" if isinstance(v, int) else "string"}">'
        f"{v if isinstance(v, int) else escape(str(v))}</{k}>"
        for k, v in fields.items()
    )
    return (
        '<?xml version="1.0"?>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body>'
        f'<q:{op}Response xmlns:q="{_NS}">{body}</q:{op}Response>'
        "</soap:Body></soap:Envelope>"
    ).encode()


class _RoutingTransport(HttpTransport):
    """Return a canned response keyed by the operation in the request body."""

    def __init__(self, responses: dict[str, bytes]) -> None:
        super().__init__()
        self._responses = responses
        self.sent: list[tuple[str, bytes, dict[str, str]]] = []

    def send(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str, bytes]:
        self.sent.append((url, body, headers))
        for op, resp in self._responses.items():
            if op.encode() in body:
                return 200, "text/xml", resp
        raise AssertionError(f"unexpected WITSML request: {body!r}")


def _client(responses: dict[str, bytes]) -> tuple[WitsmlClient, _RoutingTransport]:
    transport = _RoutingTransport(responses)
    return WitsmlClient("https://host/store", "user", "pass", transport=transport), transport


def test_options_in_builder() -> None:
    assert options_in(returnElements="id-only") == "returnElements=id-only"
    assert options_in(returnElements="all", maxReturnNodes=10) == (
        "returnElements=all;maxReturnNodes=10"
    )


def test_get_from_store_returns_xml() -> None:
    client, transport = _client(
        {
            "WMLS_GetFromStore": _resp(
                "WMLS_GetFromStore",
                {"XMLout": "<wells/>", "SuppMsgOut": "", "Result": 1},
            )
        }
    )
    out = client.get_from_store("well", "<wells/>", options=options_in(returnElements="all"))
    assert out == "<wells/>"
    # WS-Security UsernameToken + the right SOAPAction went out.
    sent = transport.sent[0]
    assert "Store.WMLS_GetFromStore" in sent[2].get("SOAPAction", "")
    assert b"UsernameToken" in sent[1]


def test_get_cap_returns_capabilities() -> None:
    client, _ = _client(
        {"WMLS_GetCap": _resp("WMLS_GetCap", {"CapabilitiesOut": "<capServers/>",
                                              "SuppMsgOut": "", "Result": 1})}
    )
    assert client.get_cap() == "<capServers/>"


def test_add_to_store_returns_code() -> None:
    client, _ = _client(
        {"WMLS_AddToStore": _resp("WMLS_AddToStore", {"SuppMsgOut": "", "Result": 1})}
    )
    assert client.add_to_store("well", "<wells><well/></wells>") == 1


def test_get_version() -> None:
    client, _ = _client(
        {"WMLS_GetVersion": _resp("WMLS_GetVersion", {"Result": "1.3.1.1,1.4.1.1"})}
    )
    assert client.get_version() == "1.3.1.1,1.4.1.1"


def test_negative_result_raises_with_resolved_message() -> None:
    client, _ = _client(
        {
            "WMLS_GetFromStore": _resp(
                "WMLS_GetFromStore", {"XMLout": "", "SuppMsgOut": "", "Result": -425}
            ),
            # The error path resolves text via WMLS_GetBaseMsg.
            "WMLS_GetBaseMsg": _resp(
                "WMLS_GetBaseMsg", {"Result": "The OptionsIn keyword is not recognized."}
            ),
        }
    )
    with pytest.raises(WitsmlError) as excinfo:
        client.get_from_store("well", "<wells/>")
    assert excinfo.value.code == -425
    assert "not recognized" in excinfo.value.message


def test_get_base_message() -> None:
    client, _ = _client(
        {"WMLS_GetBaseMsg": _resp("WMLS_GetBaseMsg", {"Result": "Function completed OK."})}
    )
    assert client.get_base_message(1) == "Function completed OK."


def test_update_in_store_returns_code() -> None:
    client, _ = _client(
        {"WMLS_UpdateInStore": _resp("WMLS_UpdateInStore", {"SuppMsgOut": "", "Result": 1})}
    )
    assert client.update_in_store("well", "<wells><well uid='1'/></wells>") == 1


def test_delete_from_store_returns_code() -> None:
    client, _ = _client(
        {"WMLS_DeleteFromStore": _resp("WMLS_DeleteFromStore", {"SuppMsgOut": "", "Result": 1})}
    )
    assert client.delete_from_store("well", "<wells><well uid='1'/></wells>") == 1


def test_context_manager_closes() -> None:
    client, _ = _client(
        {"WMLS_GetVersion": _resp("WMLS_GetVersion", {"Result": "1.4.1.1"})}
    )
    with client as wits:
        assert wits.get_version() == "1.4.1.1"


@pytest.mark.live
def test_live_get_version() -> None:
    # Point at a real WITSML 1.4.1.1 server. Run with: pytest -m live
    import os

    url = os.environ.get("WITSML_URL")
    if not url:
        pytest.skip("set WITSML_URL / WITSML_USER / WITSML_PASSWORD to run")
    with WitsmlClient(url, os.environ["WITSML_USER"], os.environ["WITSML_PASSWORD"]) as wits:
        assert wits.get_version()
