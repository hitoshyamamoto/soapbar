# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Frozen snapshot of soapbar's public API surface.

This is the freeze mechanism for the 1.0 contract. It pins two things:

1. The exact set of top-level exports (``soapbar.__all__``).
2. The signatures of the security-critical functions — parameter names *and*
   their kind (positional-or-keyword vs keyword-only).

Any addition, removal, rename, or signature change to the public surface must
update this file, which makes every such change a conscious, reviewed decision
(and a CHANGELOG entry) rather than an accident. In particular, a refactor that
silently dropped an export, or flipped a keyword-only security flag back to
positional (a subtle way to reintroduce a footgun like a positional
``require_signed_body``), fails CI here.

When you intentionally change the public surface, update the frozen sets below
in the same commit.
"""
from __future__ import annotations

import inspect

import pytest

import soapbar
from soapbar.core import wssecurity

# ---------------------------------------------------------------------------
# 1. Top-level export surface
# ---------------------------------------------------------------------------

#: The complete, frozen set of names re-exported from the ``soapbar`` package.
EXPECTED_ALL = {
    "__version__",
    # core
    "NS",
    "parse_xml",
    "parse_xml_document",
    "to_string",
    "to_bytes",
    "xsd",
    "XsdType",
    "ComplexXsdType",
    "ArrayXsdType",
    "ChoiceXsdType",
    "SoapbarError",
    "SoapFault",
    "BindingStyle",
    "OperationSignature",
    "OperationParameter",
    "get_serializer",
    "SoapEnvelope",
    "SoapHeaderBlock",
    "SoapVersion",
    "WsaHeaders",
    "WsaEndpointReference",
    "build_request",
    "build_response",
    "build_fault",
    "build_wsa_response_headers",
    "http_headers",
    "WsdlBinding",
    "WsdlBindingOperation",
    "WsdlDefinition",
    "WsdlMessage",
    "WsdlOperation",
    "WsdlOperationMessage",
    "WsdlPart",
    "WsdlPort",
    "WsdlPortType",
    "WsdlService",
    "parse_wsdl",
    "parse_wsdl_file",
    "build_wsdl",
    "build_wsdl_string",
    "build_wsdl_bytes",
    "MtomAttachment",
    "MtomMessage",
    "parse_mtom",
    "build_mtom",
    "UsernameTokenCredential",
    "UsernameTokenValidator",
    "SecurityValidationError",
    "build_binary_security_token",
    "build_security_header",
    "extract_certificate_from_security",
    "XmlSecurityError",
    "sign_element_by_id",
    "sign_envelope",
    "sign_envelope_bsp",
    "verify_envelope",
    "verify_envelope_bsp",
    "encrypt_body",
    "decrypt_body",
    # server
    "SoapService",
    "SoapApplication",
    "soap_operation",
    "AsgiSoapApp",
    "WsgiSoapApp",
    # client
    "HttpTransport",
    "SoapClient",
    "load_pkcs12",
}


def test_all_matches_frozen_set() -> None:
    actual = set(soapbar.__all__)
    removed = EXPECTED_ALL - actual
    added = actual - EXPECTED_ALL
    assert not removed, (
        f"public symbols removed from soapbar.__all__: {sorted(removed)} — "
        "removing an export is a breaking change; update EXPECTED_ALL and the CHANGELOG."
    )
    assert not added, (
        f"new public symbols in soapbar.__all__: {sorted(added)} — "
        "adding an export freezes it; update EXPECTED_ALL and the CHANGELOG."
    )


def test_all_has_no_duplicates() -> None:
    assert len(soapbar.__all__) == len(set(soapbar.__all__)), "duplicate name in __all__"


@pytest.mark.parametrize("name", sorted(EXPECTED_ALL))
def test_every_exported_name_is_importable(name: str) -> None:
    assert hasattr(soapbar, name), f"{name} is in __all__ but not importable from soapbar"


# ---------------------------------------------------------------------------
# 2. Security-critical function signatures (the WS2<->WS3 guard)
# ---------------------------------------------------------------------------


def _sig(func: object) -> list[str]:
    """Return ``["name:KIND", ...]`` for a callable's parameters, in order."""
    return [
        f"{p.name}:{p.kind.name}"
        for p in inspect.signature(func).parameters.values()  # type: ignore[arg-type]
    ]


#: Frozen signatures of the security functions. The ``KIND`` matters: flipping a
#: KEYWORD_ONLY flag back to POSITIONAL_OR_KEYWORD reopens a footgun (e.g. a
#: security switch bound by position), so it must fail here.
EXPECTED_SECURITY_SIGNATURES = {
    "sign_envelope": [
        "envelope_bytes:POSITIONAL_OR_KEYWORD",
        "private_key:POSITIONAL_OR_KEYWORD",
        "certificate:POSITIONAL_OR_KEYWORD",
    ],
    "verify_envelope": [
        "envelope_bytes:POSITIONAL_OR_KEYWORD",
        "certificate:POSITIONAL_OR_KEYWORD",
        "expected_references:KEYWORD_ONLY",
        "require_signed_body:KEYWORD_ONLY",
    ],
    "sign_envelope_bsp": [
        "envelope_bytes:POSITIONAL_OR_KEYWORD",
        "private_key:POSITIONAL_OR_KEYWORD",
        "certificate:POSITIONAL_OR_KEYWORD",
        "token_id:KEYWORD_ONLY",
    ],
    "verify_envelope_bsp": [
        "envelope_bytes:POSITIONAL_OR_KEYWORD",
        "expected_references:KEYWORD_ONLY",
        "require_signed_body:KEYWORD_ONLY",
        "trusted_certs:KEYWORD_ONLY",
        "ca_certs:KEYWORD_ONLY",
        "verify_cert_trust:KEYWORD_ONLY",
    ],
    "encrypt_body": [
        "envelope_bytes:POSITIONAL_OR_KEYWORD",
        "recipient_public_key:POSITIONAL_OR_KEYWORD",
    ],
    "decrypt_body": [
        "envelope_bytes:POSITIONAL_OR_KEYWORD",
        "private_key:POSITIONAL_OR_KEYWORD",
        "allow_unauthenticated_cbc:KEYWORD_ONLY",
    ],
    "sign_element_by_id": [
        "doc_bytes:POSITIONAL_OR_KEYWORD",
        "id_value:POSITIONAL_OR_KEYWORD",
        "private_key:POSITIONAL_OR_KEYWORD",
        "certificate:POSITIONAL_OR_KEYWORD",
        "id_attr:KEYWORD_ONLY",
        "signature_method:KEYWORD_ONLY",
        "digest_method:KEYWORD_ONLY",
        "c14n:KEYWORD_ONLY",
        "end_cert_only:KEYWORD_ONLY",
    ],
    "build_security_header": [
        "credential:POSITIONAL_OR_KEYWORD",
        "soap_ns:KEYWORD_ONLY",
        "timestamp_ttl:KEYWORD_ONLY",
    ],
    "build_binary_security_token": [
        "certificate:POSITIONAL_OR_KEYWORD",
        "token_id:KEYWORD_ONLY",
    ],
}


@pytest.mark.parametrize("name", sorted(EXPECTED_SECURITY_SIGNATURES))
def test_security_function_signatures_frozen(name: str) -> None:
    func = getattr(wssecurity, name)
    assert _sig(func) == EXPECTED_SECURITY_SIGNATURES[name], (
        f"signature of {name} changed — if intentional, update "
        "EXPECTED_SECURITY_SIGNATURES and the CHANGELOG. Never widen a "
        "KEYWORD_ONLY security parameter back to positional."
    )


# ---------------------------------------------------------------------------
# 3. Contrib client public names (importable-surface guard)
# ---------------------------------------------------------------------------

#: The key public names each contrib client module must keep exporting. Not a
#: full set-equality (the contrib modules gain a curated ``__all__`` in a later
#: workstream); this guards the client class and its typed exception hierarchy.
CONTRIB_PUBLIC_NAMES = {
    "soapbar.contrib.vies": [
        "ViesClient", "ViesResult", "ViesApproxResult", "MatchCode",
        "ViesError", "ViesInputError", "ViesRateLimitError", "ViesUnavailableError",
    ],
    "soapbar.contrib.nfe": [
        "NfeClient", "NfeStatusResult", "NfeError", "NfeInputError",
    ],
    "soapbar.contrib.ana": [
        "AnaClient", "AnaError", "AnaServiceError", "TipoDados",
    ],
    "soapbar.contrib.witsml": [
        "WitsmlClient", "WitsmlError", "WitsmlServerError",
    ],
}


@pytest.mark.parametrize("module_name", sorted(CONTRIB_PUBLIC_NAMES))
def test_contrib_public_names_importable(module_name: str) -> None:
    import importlib

    module = importlib.import_module(module_name)
    for name in CONTRIB_PUBLIC_NAMES[module_name]:
        assert hasattr(module, name), f"{module_name}.{name} is no longer importable"
