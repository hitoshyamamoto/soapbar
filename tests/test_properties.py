# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Property-based (fuzz) tests using Hypothesis.

Two kinds of properties are exercised:

* **Round-trips** — serialising a value and parsing it back must preserve it
  (XSD simple types, envelope body content, binary encodings).
* **Robustness** — parsing arbitrary or adversarial input must either succeed
  or raise a *controlled* error (lxml syntax errors, ``ValueError``,
  ``SoapbarError``); any other exception type is a bug.
"""
from __future__ import annotations

import base64
import contextlib
import math
from decimal import Decimal

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from lxml import etree

from soapbar.core.envelope import SoapEnvelope, SoapVersion, build_request
from soapbar.core.exceptions import SoapbarError
from soapbar.core.types import xsd
from soapbar.core.wsdl.parser import parse_wsdl
from soapbar.core.wssecurity import _digest_password
from soapbar.core.xml import check_xml_depth, make_element, parse_xml, sub_element, to_bytes

# Hypothesis and pytest-cov both slow individual examples down enough that the
# default 200 ms deadline produces flaky failures on loaded CI runners; the
# suite-level pytest timeout still bounds total runtime.
settings.register_profile(
    "soapbar",
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("soapbar")

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Characters valid in XML 1.0 text content that survive a parse unchanged:
# excludes control chars (lxml rejects them), carriage returns (normalised to
# newlines by the XML spec), and the two non-characters U+FFFE/U+FFFF.
xml_text = st.text(
    alphabet=st.characters(
        codec="utf-8",
        min_codepoint=0x20,
        exclude_categories=("Cs",),
        exclude_characters=("￾", "￿"),
    ) | st.sampled_from(["\t", "\n"]),
)

# NCName-shaped element names (no colon: prefixes would need namespace maps).
nc_names = st.from_regex(r"[A-Za-z_][A-Za-z0-9_.\-]{0,20}", fullmatch=True)

BOUNDED_INT_TYPES = [
    "int", "long", "short", "byte",
    "unsignedInt", "unsignedShort", "unsignedByte", "unsignedLong",
]


# ---------------------------------------------------------------------------
# XSD simple-type round-trips
# ---------------------------------------------------------------------------

class TestXsdTypeRoundTrips:
    @given(data=st.data(), name=st.sampled_from(BOUNDED_INT_TYPES))
    def test_bounded_integers_round_trip(self, data, name):
        t = xsd.resolve(name)
        v = data.draw(st.integers(min_value=t.min_value, max_value=t.max_value))
        assert t.from_xml(t.to_xml(v)) == v

    @given(data=st.data(), name=st.sampled_from(BOUNDED_INT_TYPES))
    def test_bounded_integers_reject_out_of_range(self, data, name):
        t = xsd.resolve(name)
        v = data.draw(st.one_of(
            st.integers(max_value=t.min_value - 1),
            st.integers(min_value=t.max_value + 1),
        ))
        try:
            t.to_xml(v)
        except ValueError:
            pass
        else:
            raise AssertionError(f"{name}.to_xml({v}) accepted an out-of-range value")

    @given(v=st.booleans())
    def test_boolean_round_trip(self, v):
        t = xsd.resolve("boolean")
        assert t.from_xml(t.to_xml(v)) is v

    @given(s=xml_text)
    def test_boolean_from_xml_is_total(self, s):
        """Arbitrary text either parses to a bool or raises ValueError."""
        t = xsd.resolve("boolean")
        with contextlib.suppress(ValueError):
            assert isinstance(t.from_xml(s), bool)

    @given(v=st.floats(allow_nan=False))
    def test_float_round_trip(self, v):
        t = xsd.resolve("double")
        assert t.from_xml(t.to_xml(v)) == v

    def test_float_nan_round_trip(self):
        t = xsd.resolve("double")
        assert t.to_xml(float("nan")) == "NaN"
        assert math.isnan(t.from_xml("NaN"))

    @given(v=st.decimals(min_value=Decimal("-1e12"), max_value=Decimal("1e12"),
                         allow_nan=False, allow_infinity=False, places=6))
    def test_decimal_round_trip(self, v):
        t = xsd.resolve("decimal")
        lexical = t.to_xml(v)
        assert "e" not in lexical.lower(), "xsd:decimal forbids exponent notation"
        assert t.from_xml(lexical) == v

    @given(v=st.binary())
    def test_base64_binary_round_trip(self, v):
        t = xsd.resolve("base64Binary")
        assert t.from_xml(t.to_xml(v)) == v

    @given(v=st.binary())
    def test_hex_binary_round_trip(self, v):
        t = xsd.resolve("hexBinary")
        assert t.from_xml(t.to_xml(v)) == v

    @given(v=st.datetimes())
    def test_datetime_lexical_round_trip(self, v):
        t = xsd.resolve("dateTime")
        lexical = t.to_xml(v)
        # from_xml validates and preserves the lexical form
        assert t.from_xml(lexical) == lexical

    @given(v=st.dates())
    def test_date_lexical_round_trip(self, v):
        t = xsd.resolve("date")
        assert t.from_xml(t.to_xml(v)) == v.isoformat()

    @given(s=xml_text)
    def test_datetime_from_xml_is_total(self, s):
        """Arbitrary text is either a valid lexical form or a ValueError."""
        t = xsd.resolve("dateTime")
        with contextlib.suppress(ValueError):
            t.from_xml(s)


# ---------------------------------------------------------------------------
# Envelope round-trips
# ---------------------------------------------------------------------------

class TestEnvelopeRoundTrips:
    @given(version=st.sampled_from(list(SoapVersion)), tag=nc_names,
           text=xml_text, attr=xml_text)
    def test_body_content_survives_serialise_parse(self, version, tag, text, attr):
        elem = make_element(tag, attrib={"attr": attr}, text=text)
        env = SoapEnvelope(version=version, body_elements=[elem])

        parsed = SoapEnvelope.from_xml(env.to_bytes())

        assert parsed.version is version
        (body,) = parsed.body_elements
        assert etree.QName(body).localname == tag
        assert (body.text or "") == text
        assert body.get("attr") == attr

    @given(version=st.sampled_from(list(SoapVersion)),
           texts=st.lists(xml_text, min_size=1, max_size=5))
    def test_build_request_preserves_element_count_and_order(self, version, texts):
        elems = [make_element(f"item{i}", text=t) for i, t in enumerate(texts)]
        root = build_request(version, elems)

        parsed = SoapEnvelope.from_xml(to_bytes(root))

        assert [(e.text or "") for e in parsed.body_elements] == texts


# ---------------------------------------------------------------------------
# Robustness: hostile / arbitrary input must fail in controlled ways
# ---------------------------------------------------------------------------

class TestParserRobustness:
    @given(data=st.binary(max_size=2048))
    def test_parse_xml_arbitrary_bytes(self, data):
        with contextlib.suppress(etree.XMLSyntaxError, ValueError):
            parse_xml(data)

    @given(s=xml_text.filter(lambda s: s.strip()))
    def test_parse_xml_arbitrary_text(self, s):
        with contextlib.suppress(etree.XMLSyntaxError, ValueError):
            parse_xml(s)

    @given(data=st.binary(max_size=2048))
    def test_envelope_from_xml_arbitrary_bytes(self, data):
        with contextlib.suppress(etree.XMLSyntaxError, ValueError, SoapbarError):
            SoapEnvelope.from_xml(data)

    @given(data=st.binary(max_size=2048))
    def test_parse_wsdl_arbitrary_bytes(self, data):
        with contextlib.suppress(etree.XMLSyntaxError, ValueError, SoapbarError):
            parse_wsdl(data)

    @given(tag=nc_names, children=st.lists(nc_names, max_size=8), text=xml_text)
    def test_parse_wsdl_arbitrary_wellformed_xml(self, tag, children, text):
        """Well-formed but non-WSDL XML must parse to a definition or raise a
        controlled error — never an unhandled crash."""
        root = make_element(tag, text=text)
        for child in children:
            sub_element(root, child, text=text)
        with contextlib.suppress(ValueError, SoapbarError):
            parse_wsdl(to_bytes(root))

    @given(depth=st.integers(min_value=1, max_value=60))
    def test_check_xml_depth_counts_nesting_exactly(self, depth):
        limit = 30
        doc = ("<a>" * depth) + ("</a>" * depth)
        if depth > limit:
            try:
                check_xml_depth(doc.encode(), max_depth=limit)
            except ValueError:
                pass
            else:
                raise AssertionError(f"depth {depth} accepted with limit {limit}")
        else:
            check_xml_depth(doc.encode(), max_depth=limit)


# ---------------------------------------------------------------------------
# WS-Security digest
# ---------------------------------------------------------------------------

class TestPasswordDigest:
    @given(nonce=st.binary(min_size=1, max_size=64), created=xml_text,
           password=xml_text)
    def test_digest_is_deterministic_valid_base64_sha1(self, nonce, created, password):
        d1 = _digest_password(nonce, created, password)
        d2 = _digest_password(nonce, created, password)
        assert d1 == d2
        assert len(base64.b64decode(d1)) == 20  # SHA-1 digest size
