"""MTOM/XOP multipart SOAP message parsing and building.

Implements W3C MTOM (Message Transmission Optimization Mechanism) and
XOP (XML-binary Optimized Packaging) per:
- W3C MTOM: https://www.w3.org/TR/soap12-mtom/
- W3C XOP:  https://www.w3.org/TR/xop10/
"""
from __future__ import annotations

import base64
import email.parser
import email.policy
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from soapbar.core.namespaces import NS


@dataclass
class MtomAttachment:
    """A single MIME part / XOP attachment."""

    content_id: str          # bare Content-ID (without angle brackets)
    content_type: str
    data: bytes


@dataclass
class MtomMessage:
    """Parsed MTOM multipart message."""

    soap_xml: bytes                            # XOP-include-resolved SOAP envelope bytes
    attachments: list[MtomAttachment] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _strip_angle(cid: str) -> str:
    """Remove surrounding <…> from a Content-ID value."""
    return cid.strip().lstrip("<").rstrip(">")


def _mime_boundary(content_type: str) -> str | None:
    """Extract the boundary parameter from a Content-Type header."""
    m = re.search(r'boundary="?([^";]+)"?', content_type, re.IGNORECASE)
    return m.group(1) if m else None


def parse_mtom(raw: bytes, content_type: str) -> MtomMessage:
    """Parse a multipart/related MTOM message.

    The first MIME part is expected to be the SOAP envelope (application/xop+xml).
    Subsequent parts are binary attachments.  All ``<xop:Include>`` elements in the
    envelope are resolved inline so that the returned ``soap_xml`` is a plain XML
    document that the rest of the stack can handle without special cases.

    Args:
        raw: The raw HTTP response/request body (all MIME parts concatenated).
        content_type: The value of the ``Content-Type`` header for the whole body.

    Returns:
        An :class:`MtomMessage` with resolved XML and the list of attachments.

    Raises:
        ValueError: If the message cannot be parsed as a valid MTOM envelope.
    """
    boundary = _mime_boundary(content_type)
    if boundary is None:
        raise ValueError("No MIME boundary found in Content-Type")

    # email.parser wants headers+body together; prepend a dummy header so that
    # the multipart structure is recognised correctly.
    fake_headers = (
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode()
    msg = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(
        fake_headers + raw
    )

    parts = list(msg.walk())
    # parts[0] is the outer multipart container; payload parts start at index 1
    payload_parts = [p for p in parts if not p.is_multipart()]
    if not payload_parts:
        raise ValueError("MTOM message contains no MIME parts")

    # --- Build CID → attachment index for xop:Include resolution
    attachments: list[MtomAttachment] = []
    attachment_map: dict[str, int] = {}      # cid (no angle brackets) → index

    for part in payload_parts[1:]:
        raw_cid = part.get("Content-ID", "")
        cid = _strip_angle(raw_cid)
        ct = part.get_content_type()
        raw_data = part.get_payload(decode=True)
        data: bytes = raw_data if isinstance(raw_data, bytes) else b""
        idx = len(attachments)
        attachments.append(MtomAttachment(content_id=cid, content_type=ct, data=data))
        if cid:
            attachment_map[cid] = idx

    # --- Get the SOAP XML part (first payload part)
    soap_part = payload_parts[0]
    raw_soap = soap_part.get_payload(decode=True)
    soap_bytes: bytes = raw_soap if isinstance(raw_soap, bytes) else b""

    # --- Resolve xop:Include inline
    soap_bytes = _resolve_xop_includes(soap_bytes, attachments, attachment_map)

    return MtomMessage(soap_xml=soap_bytes, attachments=attachments)


def _resolve_xop_includes(
    xml_bytes: bytes,
    attachments: list[MtomAttachment],
    attachment_map: dict[str, int],
) -> bytes:
    """Replace every ``<xop:Include href="cid:…"/>`` with the base64-encoded
    attachment data so the result is a self-contained XML document."""
    from lxml import etree

    from soapbar.core.xml import parse_xml

    root = parse_xml(xml_bytes)
    xop_include_tag = f"{{{NS.XOP}}}Include"

    for elem in root.iter(xop_include_tag):
        href = elem.get("href", "")
        cid = href[4:] if href.startswith("cid:") else href

        idx = attachment_map.get(cid)
        if idx is not None:
            data = attachments[idx].data
            encoded = base64.b64encode(data).decode()
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
                parent.text = (parent.text or "") + encoded

    return etree.tostring(root, xml_declaration=True, encoding="utf-8")


# ---------------------------------------------------------------------------
# Building helpers
# ---------------------------------------------------------------------------

def build_mtom(
    soap_xml: bytes,
    attachments: list[MtomAttachment],
    soap_version_content_type: str = "application/soap+xml",
    soap_action: str = "",
) -> tuple[bytes, str]:
    """Package a SOAP envelope and binary attachments as an MTOM multipart message.

    For each attachment a ``<xop:Include>`` element is NOT automatically inserted —
    callers are expected to have already placed ``<xop:Include href="cid:…"/>`` elements
    inside the SOAP body where they want binary data substituted.  This function simply
    assembles the MIME package.

    Args:
        soap_xml: The SOAP XML bytes (may already contain xop:Include references).
        attachments: List of binary attachments to include as MIME parts.
        soap_version_content_type: ``text/xml`` (SOAP 1.1) or
            ``application/soap+xml`` (SOAP 1.2).
        soap_action: Optional SOAPAction / action URI for the ``start-info`` parameter.

    Returns:
        A ``(body_bytes, content_type_header)`` tuple ready for use as an HTTP body.
    """
    boundary = f"MIMEBoundary_{uuid.uuid4().hex}"

    def crlf(s: str) -> bytes:
        return s.replace("\n", "\r\n").encode()

    parts: list[bytes] = []

    # --- Root SOAP part (application/xop+xml)
    action_param = f'; action="{soap_action}"' if soap_action else ""
    soap_ct = (
        f'application/xop+xml; charset=utf-8; '
        f'type="{soap_version_content_type}"{action_param}'
    )
    root_part = crlf(
        f"Content-Type: {soap_ct}\n"
        f"Content-Transfer-Encoding: 8bit\n"
        f"Content-ID: <rootpart@soapbar>\n"
        "\n"
    ) + soap_xml

    parts.append(root_part)

    # --- Attachment parts
    for att in attachments:
        cid_header = f"<{att.content_id}>"
        att_part = crlf(
            f"Content-Type: {att.content_type}\n"
            f"Content-Transfer-Encoding: binary\n"
            f"Content-ID: {cid_header}\n"
            "\n"
        ) + att.data
        parts.append(att_part)

    sep = f"--{boundary}\r\n".encode()
    end = f"--{boundary}--\r\n".encode()

    body = sep + (b"\r\n" + sep).join(parts) + b"\r\n" + end

    # The outer Content-Type includes start= pointing to the SOAP root part
    outer_ct = (
        f'multipart/related; type="application/xop+xml"; '
        f'boundary="{boundary}"; '
        f'start="<rootpart@soapbar>"; '
        f'start-info="{soap_version_content_type}"'
    )
    if soap_action:
        outer_ct += f'; action="{soap_action}"'

    return body, outer_ct


def extract_xop_elements(xml_bytes: bytes) -> list[tuple[str, Any]]:
    """Return a list of ``(parent_tag, xop_include_element)`` tuples found in
    ``xml_bytes``.  Useful for inspecting which elements contain XOP references
    before resolving them."""
    from soapbar.core.xml import parse_xml

    root = parse_xml(xml_bytes)
    xop_tag = f"{{{NS.XOP}}}Include"
    result = []
    for elem in root.iter(xop_tag):
        parent = elem.getparent()
        raw_tag = parent.tag if parent is not None else ""
        parent_tag = raw_tag if isinstance(raw_tag, str) else str(raw_tag)
        result.append((parent_tag, elem))
    return result
