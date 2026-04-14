"""Walk a WSDL and print its services / bindings / operations / messages.

Useful when integrating with a third-party SOAP service: dump the contract
to see what's available before writing any client code.

Run (against the calculator from 01_calculator):
    uv run python examples/01_calculator/server_fastapi.py &
    uv run python examples/16_introspection/inspect_wsdl.py http://127.0.0.1:8000/soap?wsdl
"""
from __future__ import annotations

import sys

import httpx

from soapbar.core.wsdl import parse_wsdl


def main(wsdl_url: str) -> None:
    raw = httpx.get(wsdl_url).content
    defn = parse_wsdl(raw)

    print(f"WSDL: {defn.name!r}  targetNamespace={defn.target_namespace!r}\n")

    print(f"services ({len(defn.services)}):")
    for sname, svc in defn.services.items():
        print(f"  - {sname}")
        for port in svc.ports:
            print(f"      port {port.name}  binding={port.binding_name}  address={port.address}")

    print(f"\nport_types ({len(defn.port_types)}):")
    for pname, pt in defn.port_types.items():
        print(f"  - {pname}")
        for op in pt.operations:
            print(f"      op {op.name}  input={op.input.message_qname}  "
                  f"output={op.output.message_qname if op.output else None}")

    print(f"\nbindings ({len(defn.bindings)}):")
    for bname, b in defn.bindings.items():
        print(f"  - {bname}  soap_ns={b.soap_ns}")
        for op in b.operations:
            print(f"      op {op.name}  style={op.style}  use={op.input_use}  "
                  f"action={op.soap_action!r}")

    print(f"\nmessages ({len(defn.messages)}):")
    for mname, msg in defn.messages.items():
        parts = ", ".join(f"{p.name}:{p.element_qname or p.type_qname}" for p in msg.parts)
        print(f"  - {mname}  parts=[{parts}]")

    print(f"\ncomplex_types ({len(defn.complex_types)}):")
    for tname in defn.complex_types:
        print(f"  - {tname}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: inspect_wsdl.py <wsdl-url-or-file>")
    main(sys.argv[1])
