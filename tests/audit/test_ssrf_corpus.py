"""Adversarial SSRF corpus for WSDL/XSD import resolution.

Why this file exists
--------------------
CVE-2026-58501 in zeep was not "no guard" — it was ``Settings.forbid_external``
being *defined but not enforced* on transitive ``xsd:import`` / ``xsd:include``
/ ``wsdl:import`` and lxml entity/DTD references. A test that asserts
"raises ValueError" would not have caught it, because the bypassing code path
never reached the raise.

So every test here asserts on the **sentinel server's request log**: the
invariant is *no packet left the process*, not *an exception was raised*.
That is the only assertion shape that catches a silently-bypassed guard.

Run: pytest tests/audit/test_ssrf_corpus.py -v --no-cov
"""

from __future__ import annotations

import contextlib
import http.server
import socketserver
import threading
from pathlib import Path
from typing import ClassVar

import pytest

from soapbar import parse_wsdl, parse_wsdl_file

# --------------------------------------------------------------------------
# Sentinel: any request that reaches this server is a guard failure.
# --------------------------------------------------------------------------


class _SentinelHandler(http.server.BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        body = (
            b'<?xml version="1.0"?>'
            b'<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def sentinel():
    """Yield the sentinel base URL; fail the test if anything hit it."""
    _SentinelHandler.hits = []
    server = socketserver.TCPServer(("127.0.0.1", 0), _SentinelHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        assert _SentinelHandler.hits == [], (
            f"SSRF guard bypassed — outbound request(s) escaped: "
            f"{_SentinelHandler.hits}"
        )


def _wsdl(body: str = "", types: str = "") -> bytes:
    return f"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:xsd="http://www.w3.org/2001/XMLSchema"
             targetNamespace="urn:t">
  {body}
  <types><xsd:schema targetNamespace="urn:t">{types}</xsd:schema></types>
</definitions>""".encode()


# --------------------------------------------------------------------------
# Direct import vectors — parse_wsdl (untrusted, in-memory)
# --------------------------------------------------------------------------


def test_wsdl_import_remote_blocked(sentinel):
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl(_wsdl(body=f'<import namespace="urn:x" location="{sentinel}/a.wsdl"/>'))


def test_xsd_import_remote_blocked(sentinel):
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl(
            _wsdl(types=f'<xsd:import namespace="urn:x" schemaLocation="{sentinel}/a.xsd"/>')
        )


def test_xsd_include_remote_blocked(sentinel):
    """include is a separate element from import — regression guard."""
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl(_wsdl(types=f'<xsd:include schemaLocation="{sentinel}/a.xsd"/>'))


def test_relative_location_with_hostile_base_url_blocked(sentinel):
    """urljoin turns a relative schemaLocation into a remote one."""
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl(
            _wsdl(types='<xsd:import namespace="urn:x" schemaLocation="a.xsd"/>'),
            base_url=f"{sentinel}/dir/",
        )


def test_strict_false_does_not_bypass_guard(sentinel):
    """The permissive path must not swallow the guard into a warning."""
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl(
            _wsdl(types=f'<xsd:import namespace="urn:x" schemaLocation="{sentinel}/a.xsd"/>'),
            strict=False,
        )


@pytest.mark.parametrize(
    "location",
    ["file:///etc/passwd", "/etc/passwd", "../../../../etc/passwd"],
)
def test_local_read_blocked_for_in_memory_wsdl(sentinel, location):
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl(_wsdl(types=f'<xsd:import namespace="urn:x" schemaLocation="{location}"/>'))


# --------------------------------------------------------------------------
# Entity / DTD vectors — must be inert, not merely non-fatal
# --------------------------------------------------------------------------


def test_doctype_system_remote_not_fetched(sentinel):
    src = (
        f'<?xml version="1.0"?><!DOCTYPE definitions SYSTEM "{sentinel}/evil.dtd">'
        '<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:t"/>'
    )
    # Outcome irrelevant; the fixture asserts no fetch happened.
    with contextlib.suppress(Exception):
        parse_wsdl(src.encode())


def test_external_general_entity_not_fetched(sentinel):
    src = f"""<?xml version="1.0"?>
<!DOCTYPE definitions [<!ENTITY xxe SYSTEM "{sentinel}/xxe">]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:t">
<documentation>&xxe;</documentation></definitions>"""
    with contextlib.suppress(Exception):
        parse_wsdl(src.encode())


def test_parameter_entity_not_fetched(sentinel):
    src = f"""<?xml version="1.0"?>
<!DOCTYPE definitions [<!ENTITY % ext SYSTEM "{sentinel}/pe.dtd"> %ext;]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" targetNamespace="urn:t"/>"""
    with contextlib.suppress(Exception):
        parse_wsdl(src.encode())


def test_xsi_schemalocation_not_fetched(sentinel):
    src = f"""<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:t {sentinel}/s.xsd" targetNamespace="urn:t"/>"""
    with contextlib.suppress(Exception):
        parse_wsdl(src.encode())


# --------------------------------------------------------------------------
# Transitive vectors — the exact zeep failure mode
# --------------------------------------------------------------------------


def test_transitive_local_to_remote_blocked(sentinel, tmp_path: Path):
    """Trusted local WSDL -> local XSD -> REMOTE XSD."""
    (tmp_path / "inner.xsd").write_text(
        f'<?xml version="1.0"?>'
        f'<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:i">'
        f'<xs:import namespace="urn:x" schemaLocation="{sentinel}/deep.xsd"/></xs:schema>'
    )
    outer = tmp_path / "outer.wsdl"
    outer.write_bytes(_wsdl(types='<xsd:import namespace="urn:i" schemaLocation="inner.xsd"/>'))
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl_file(str(outer))


def test_transitive_three_levels_via_include_blocked(sentinel, tmp_path: Path):
    (tmp_path / "mid.xsd").write_text(
        f'<?xml version="1.0"?>'
        f'<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:m">'
        f'<xs:include schemaLocation="{sentinel}/lvl3.xsd"/></xs:schema>'
    )
    (tmp_path / "inner2.xsd").write_text(
        '<?xml version="1.0"?>'
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:i2">'
        '<xs:include schemaLocation="mid.xsd"/></xs:schema>'
    )
    outer = tmp_path / "outer2.wsdl"
    outer.write_bytes(_wsdl(types='<xsd:import namespace="urn:i2" schemaLocation="inner2.xsd"/>'))
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl_file(str(outer))


def test_transitive_wsdl_import_local_to_remote_blocked(sentinel, tmp_path: Path):
    (tmp_path / "w_inner.wsdl").write_bytes(
        _wsdl(body=f'<import namespace="urn:x" location="{sentinel}/deep.wsdl"/>')
    )
    outer = tmp_path / "w_outer.wsdl"
    outer.write_bytes(_wsdl(body='<import namespace="urn:i" location="w_inner.wsdl"/>'))
    with pytest.raises(ValueError, match=r"(?i)blocked"):
        parse_wsdl_file(str(outer))


# --------------------------------------------------------------------------
# FINDING 1 — path confinement (fixed by the root_dir confinement guard).
# --------------------------------------------------------------------------


def test_parse_wsdl_file_confines_imports_to_root_dir(tmp_path: Path):
    outside = tmp_path.parent / "soapbar_confine_probe.xsd"
    outside.write_text(
        '<?xml version="1.0"?>'
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:leak">'
        '<xs:complexType name="LEAKED"><xs:sequence/></xs:complexType></xs:schema>'
    )
    try:
        wsdl = tmp_path / "t.wsdl"
        wsdl.write_bytes(
            _wsdl(types=f'<xsd:import namespace="urn:leak" schemaLocation="../{outside.name}"/>')
        )
        with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
            parse_wsdl_file(str(wsdl))
    finally:
        outside.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# FINDING 2 — redirect following (fixed by the no-redirect opener).
# --------------------------------------------------------------------------


class _RedirHandler(http.server.BaseHTTPRequestHandler):
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        if self.path == "/redir":
            self.send_response(302)
            target = f"http://127.0.0.1:{self.server.server_address[1]}/INTERNAL"
            self.send_header("Location", target)
            self.end_headers()
            return
        body = b'<?xml version="1.0"?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"/>'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def test_remote_import_does_not_follow_redirects():
    _RedirHandler.hits = []
    server = socketserver.TCPServer(("127.0.0.1", 0), _RedirHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with contextlib.suppress(Exception):
            parse_wsdl(
                _wsdl(
                    types=(
                        f'<xsd:import namespace="urn:x" '
                        f'schemaLocation="http://127.0.0.1:{port}/redir"/>'
                    )
                ),
                allow_remote_imports=True,
            )
        assert not any("INTERNAL" in h for h in _RedirHandler.hits), (
            f"redirect followed to an unauthorised target: {_RedirHandler.hits}"
        )
    finally:
        server.shutdown()
        server.server_close()
