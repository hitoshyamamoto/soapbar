# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Hardened XML utilities built on lxml."""
from __future__ import annotations

from pathlib import Path

from lxml import etree
from lxml.etree import _Element

# ---------------------------------------------------------------------------
# Hardened parser factory
# ---------------------------------------------------------------------------

def _make_parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        load_dtd=False,
        dtd_validation=False,
        remove_comments=True,
        remove_pis=True,
    )


_PARSER = _make_parser()


# ---------------------------------------------------------------------------
# Element construction
# ---------------------------------------------------------------------------

def make_element(
    tag: str,
    attrib: dict[str, str] | None = None,
    nsmap: dict[str | None, str] | None = None,
    text: str | None = None,
) -> _Element:
    elem = etree.Element(tag, attrib=attrib or {}, nsmap=nsmap or {})
    if text is not None:
        elem.text = text
    return elem


def sub_element(
    parent: _Element,
    tag: str,
    attrib: dict[str, str] | None = None,
    nsmap: dict[str | None, str] | None = None,
    text: str | None = None,
) -> _Element:
    elem = etree.SubElement(parent, tag, attrib=attrib or {}, nsmap=nsmap or {})
    if text is not None:
        elem.text = text
    return elem


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def check_xml_depth(data: bytes, max_depth: int = 100) -> None:
    """Raise ValueError if the XML nesting depth exceeds *max_depth*.

    Uses ``iterparse`` so the check runs before a full parse tree is built,
    limiting memory exposure from pathologically nested documents.

    :raises ValueError: if depth > max_depth (caller converts to SoapFault).
    """
    from io import BytesIO
    depth = 0
    for event, _ in etree.iterparse(BytesIO(data), events=("start", "end"),
                                    recover=False, resolve_entities=False,
                                    load_dtd=False, no_network=True):
        if event == "start":
            depth += 1
            if depth > max_depth:
                raise ValueError(
                    f"XML nesting depth exceeds limit ({max_depth})"
                )
        else:
            depth -= 1


def parse_xml(data: str | bytes) -> _Element:
    if isinstance(data, str):
        data = data.encode()
    return etree.fromstring(data, parser=_PARSER)


def parse_xml_file(path: str | Path) -> _Element:
    tree = etree.parse(str(path), parser=_PARSER)
    return tree.getroot()


def parse_xml_document(source: str | bytes | Path | _Element) -> _Element:
    if isinstance(source, _Element):
        return source
    if isinstance(source, Path):
        return parse_xml_file(source)
    return parse_xml(source)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def to_string(elem: _Element, pretty_print: bool = False) -> str:
    return etree.tostring(elem, pretty_print=pretty_print, encoding="unicode")


def to_bytes(
    elem: _Element,
    pretty_print: bool = False,
    xml_declaration: bool = True,
) -> bytes:
    return etree.tostring(
        elem,
        pretty_print=pretty_print,
        xml_declaration=xml_declaration,
        encoding="UTF-8",
    )


# ---------------------------------------------------------------------------
# Namespace helpers
# ---------------------------------------------------------------------------

def build_nsmap(*pairs: tuple[str | None, str]) -> dict[str | None, str]:
    return dict(pairs)


def collect_namespaces(elem: _Element) -> dict[str, str]:
    """Return all namespaces visible at this element."""
    return dict(elem.nsmap)  # type: ignore[arg-type]


def local_name(elem: _Element) -> str:
    return etree.QName(elem.tag).localname  # type: ignore[arg-type]


def namespace_uri(elem: _Element) -> str | None:
    return etree.QName(elem.tag).namespace  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# XPath / search helpers
# ---------------------------------------------------------------------------

def find(elem: _Element, path: str, nsmap: dict[str, str] | None = None) -> _Element | None:
    return elem.find(path, nsmap)


def findall(elem: _Element, path: str, nsmap: dict[str, str] | None = None) -> list[_Element]:
    return elem.findall(path, nsmap)


def findtext(elem: _Element, path: str, nsmap: dict[str, str] | None = None) -> str | None:
    return elem.findtext(path, namespaces=nsmap)


def get_attr(elem: _Element, key: str, default: str | None = None) -> str | None:
    return elem.get(key, default)


def set_attr(elem: _Element, key: str, value: str) -> None:
    elem.set(key, value)


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def compile_schema(schema_element: _Element) -> etree.XMLSchema:
    return etree.XMLSchema(schema_element)


def validate_schema(schema: etree.XMLSchema, elem: _Element) -> bool:
    return schema.validate(elem)


def clone(elem: _Element) -> _Element:
    import copy
    return copy.deepcopy(elem)


__all__ = [
    "_Element",
    "build_nsmap",
    "check_xml_depth",
    "clone",
    "collect_namespaces",
    "compile_schema",
    "find",
    "findall",
    "findtext",
    "get_attr",
    "local_name",
    "make_element",
    "namespace_uri",
    "parse_xml",
    "parse_xml_document",
    "parse_xml_file",
    "set_attr",
    "sub_element",
    "to_bytes",
    "to_string",
    "validate_schema",
]
