"""WS-Addressing client — demonstrates ``use_wsa=True`` and the
``WSA_ANONYMOUS`` / ``WSA_NONE`` magic-URI constants (WS-Addressing 1.0 §2.1).

``use_wsa=True`` makes SoapClient emit a ``wsa:MessageID`` + ``wsa:Action`` on
every request; the constants below are the canonical addresses a client uses
for "reply to the sender" and "don't reply at all".  Router/intermediary code
should short-circuit those values before attempting to dispatch.

Run:
    uv run python examples/05_ws_addressing/server.py &
    uv run python examples/05_ws_addressing/client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.core.envelope import WSA_ANONYMOUS, WSA_NONE


def main() -> None:
    print("WS-Addressing magic URIs (WS-Addressing 1.0 §2.1):")
    print(f"  WSA_ANONYMOUS = {WSA_ANONYMOUS}")
    print(f"  WSA_NONE      = {WSA_NONE}")
    print()

    client = SoapClient(
        wsdl_url="http://127.0.0.1:8005/soap?wsdl",
        use_wsa=True,
    )
    result = client.call("ping", msg="hi from WS-A client")
    print(f"server replied: {result}")


if __name__ == "__main__":
    main()
