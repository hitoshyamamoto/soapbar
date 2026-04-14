"""Client for the complex-types example — sends a User dict, prints the reply.

Run:
    uv run python examples/10_complex_types/server.py &
    uv run python examples/10_complex_types/client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient


def main() -> None:
    client = SoapClient(wsdl_url="http://127.0.0.1:8010/soap?wsdl")

    sent = {"name": "Ada Lovelace", "email": "Ada@EXAMPLE.com", "age": 36}
    print(f"sent:    {sent}")

    reply = client.call("create_user", user=sent)
    print(f"reply:   {reply}")


if __name__ == "__main__":
    main()
