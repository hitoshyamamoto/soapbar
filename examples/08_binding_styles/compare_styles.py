"""Side-by-side wire format for every BindingStyle soapbar supports.

WSDL bindings come in five flavors that change how the operation arguments
appear inside ``soap:Body``:

- ``DOCUMENT_LITERAL_WRAPPED`` — WS-I BP default; wrapper element + literal
  XSD-typed children.  Most modern stacks expect this.
- ``DOCUMENT_LITERAL`` (bare) — no wrapper; one body-level element per
  message part.
- ``RPC_LITERAL`` — RPC wrapper element named after the operation; literal
  parameter children.  Common for legacy services.
- ``RPC_ENCODED`` — RPC wrapper, plus SOAP §5 ``xsi:type`` annotations on
  every value.  Required by some Java / .NET legacy stacks.
- ``DOCUMENT_ENCODED`` — rare.  Document framing with §5 encoded values.

This script serializes the same ``Add(a=3, b=4)`` request through each style
and prints the resulting Body content so the differences are visible at a
glance.

Run:
    uv run python examples/08_binding_styles/compare_styles.py
"""
from __future__ import annotations

from lxml import etree

from soapbar.core.binding import (
    BindingStyle,
    OperationParameter,
    OperationSignature,
    get_serializer,
)
from soapbar.core.types import xsd

INT = xsd.resolve("int")
assert INT is not None

SIG = OperationSignature(
    name="Add",
    input_params=[OperationParameter("a", INT), OperationParameter("b", INT)],
    output_params=[OperationParameter("result", INT)],
)


def render(style: BindingStyle) -> str:
    serializer = get_serializer(style)
    container = etree.Element("_body")
    serializer.serialize_request(SIG, {"a": 3, "b": 4}, container)
    return etree.tostring(container, pretty_print=True).decode()


def main() -> None:
    for style in BindingStyle:
        flag = (
            f"  is_rpc={style.is_rpc}, is_encoded={style.is_encoded}, "
            f"is_wrapped={style.is_wrapped}"
        )
        print(f"=== {style.name} ===")
        print(flag)
        # serialize_request writes into the temp <_body/> wrapper; strip the
        # outer element when printing so the per-style differences are stark.
        rendered = render(style)
        # Drop the <_body> open/close tags and re-indent.
        rendered = rendered.replace("<_body>\n  ", "").replace("\n</_body>\n", "\n")
        print(rendered)


if __name__ == "__main__":
    main()
