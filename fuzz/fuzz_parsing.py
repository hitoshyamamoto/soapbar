#!/usr/bin/env python3
# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Atheris (libFuzzer) harness for soapbar's parsing entry points.

Feeds coverage-guided arbitrary bytes into every parser that accepts
untrusted input — ``parse_xml``, ``check_xml_depth``,
``SoapEnvelope.from_xml`` and ``parse_wsdl`` — and treats any exception
other than the documented controlled errors (lxml syntax/parse errors,
``ValueError``, ``SoapbarError``) as a crash.

Atheris >= 3.1 only ships wheels for CPython 3.12+, so run under 3.12+::

    uv run --group fuzz python fuzz/fuzz_parsing.py

Standard libFuzzer flags apply, e.g. ``-max_total_time=300`` or a corpus
directory as a positional argument. The scheduled ``fuzz.yml`` workflow
runs this harness weekly; tests/test_properties.py holds the
Hypothesis-based structured-input properties that complement it.
"""
import contextlib
import sys

import atheris

with atheris.instrument_imports():
    from soapbar.core.envelope import SoapEnvelope
    from soapbar.core.exceptions import SoapbarError
    from soapbar.core.wsdl.parser import parse_wsdl
    from soapbar.core.xml import check_xml_depth, parse_xml

from lxml import etree

# The documented failure contract for hostile input. XMLSyntaxError does not
# subclass ValueError, so lxml's base error is listed explicitly.
CONTROLLED_ERRORS = (etree.LxmlError, ValueError, SoapbarError)


def TestOneInput(data: bytes) -> None:  # noqa: N802 — atheris entry-point convention
    with contextlib.suppress(*CONTROLLED_ERRORS):
        check_xml_depth(data, max_depth=50)

    with contextlib.suppress(*CONTROLLED_ERRORS):
        parse_xml(data)

    with contextlib.suppress(*CONTROLLED_ERRORS):
        SoapEnvelope.from_xml(data)

    with contextlib.suppress(*CONTROLLED_ERRORS):
        parse_wsdl(data)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
