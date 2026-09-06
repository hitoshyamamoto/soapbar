# WSDL object model

`parse_wsdl` / `parse_wsdl_file` return a `WsdlDefinition` — the root of a
small graph of dataclasses mirroring WSDL 1.1's own structure. Every type in
that graph is exported from the `soapbar` top level, so code that walks a
parsed contract never needs deep imports. This page is the map of the graph;
field-by-field reference lives in the [API reference](api.md).

## The graph

Two axes hang off `WsdlDefinition`, joined by name references:

```
WsdlDefinition
├── services:   dict[str, WsdlService]      # who answers, and where
│   └── ports:  list[WsdlPort]              #   .name, .binding (name ref), .address
├── bindings:   dict[str, WsdlBinding]      # how the wire looks
│   └── operations: list[WsdlBindingOperation]   # .name, .soap_action, .style, .use
├── port_types: dict[str, WsdlPortType]     # the abstract interface
│   └── operations: list[WsdlOperation]     # .name, .input/.output/.faults
│       └── WsdlOperationMessage            #   .message (name ref into messages)
├── messages:   dict[str, WsdlMessage]      # what each message carries
│   └── parts:  list[WsdlPart]              #   .name, .element or .type
└── complex_types: dict[str, XsdType]       # types harvested from <wsdl:types>
```

A `WsdlPort.binding` names an entry in `bindings`; a
`WsdlOperationMessage.message` names an entry in `messages`. Concrete detail
(SOAP version, `soapAction`, style) lives on the binding axis; the abstract
shape (which messages, which parts, which schema types) lives on the
portType/message axis.

## Answering the questions you actually have

The script below runs as-is against the VIES WSDL bundled with soapbar
(`soapbar[vies]` not required — the file ships in the wheel):

```python
from importlib import resources

from soapbar import ArrayXsdType, ChoiceXsdType, parse_wsdl_file

wsdl = resources.files("soapbar.contrib").joinpath("_wsdl/checkVatService.wsdl")
with resources.as_file(wsdl) as path:
    defn = parse_wsdl_file(path)

# Which services and endpoints does this document offer?
for service in defn.services.values():
    for port in service.ports:
        print(f"service {service.name!r}: port {port.name!r} -> {port.address}")

# Which operations exist, and what is each one's soapAction and style?
for binding in defn.bindings.values():
    print(f"binding {binding.name!r}: style={binding.style!r}")
    for op in binding.operations:
        print(f"  operation {op.name!r}: soapAction={op.soap_action!r}")

# What goes in and out of an operation? Follow the portType axis.
for pt in defn.port_types.values():
    for op in pt.operations:
        for direction, msg_ref in (("in", op.input), ("out", op.output)):
            if msg_ref is None:
                continue
            message = defn.messages[msg_ref.message]
            parts = [(p.name, p.element or p.type) for p in message.parts]
            print(f"{op.name} {direction}: {parts}")

# Parser-produced complex types (see the type system page)
for name, ct in defn.complex_types.items():
    if isinstance(ct, (ArrayXsdType, ChoiceXsdType)):
        print(f"complex type {name!r}: {type(ct).__name__}")
```

Output (VIES):

```
service 'checkVatService': port 'checkVatPort' -> http://ec.europa.eu/taxation_customs/vies/services/checkVatService
binding 'checkVatBinding': style='document'
  operation 'checkVat': soapAction=''
  operation 'checkVatApprox': soapAction=''
checkVat in: [('parameters', 'tns1:checkVat')]
checkVat out: [('parameters', 'tns1:checkVatResponse')]
checkVatApprox in: [('parameters', 'tns1:checkVatApprox')]
checkVatApprox out: [('parameters', 'tns1:checkVatApproxResponse')]
```

Reading it: one service with one port pointing at the EC endpoint; a
document-style binding whose two operations use an empty `soapAction` (VIES
dispatches on the body element); and each operation's message carries a
single `parameters` part referencing a schema element — the
document/literal-wrapped shape, which is why `SoapClient` drives this WSDL
with wrapped calls.

`WsdlDefinition.complex_types` holds every named type harvested from the
`<wsdl:types>` schemas, including the parser-produced
[`ArrayXsdType` and `ChoiceXsdType`](types.md#parser-produced-complex-types).
The binding-level `WsdlBindingOperation.style`/`.use` pair is what
`SoapClient` uses to pick a binding style; `WsdlPart.element` (versus
`.type`) is the document-versus-RPC signal at the message level.
