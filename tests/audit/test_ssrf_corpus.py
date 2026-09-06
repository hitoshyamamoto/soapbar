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
import os
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


_LEAK_XSD = (
    '<?xml version="1.0"?>'
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" '
    'targetNamespace="urn:leak">'
    '<xs:complexType name="CONFINEMENT_ESCAPED"><xs:sequence/></xs:complexType>'
    "</xs:schema>"
)


def _wsdl_importing(location: str) -> bytes:
    """A WSDL whose single xsd:import points at *location*."""
    return _wsdl(types=f'<xsd:import namespace="urn:leak" schemaLocation="{location}"/>')


def _assert_escaped_or_not_read(defn) -> None:
    """Fail if the out-of-tree schema's type made it into the definition."""
    assert "CONFINEMENT_ESCAPED" not in (getattr(defn, "complex_types", {}) or {}), (
        "path-confinement guard bypassed: an out-of-tree schema was imported"
    )


# --------------------------------------------------------------------------
# Path-confinement escape vectors. Each must raise; none may import the type.
# --------------------------------------------------------------------------


def test_confinement_blocks_file_symlink_escape(tmp_path: Path):
    """A symlink inside the tree pointing at a file outside it.

    resolve() must be applied before the containment comparison, or a
    symlink walks straight out.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.xsd").write_text(_LEAK_XSD)
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside / "secret.xsd", root / "link.xsd")

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("link.xsd"))
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


def test_confinement_blocks_directory_symlink_escape(tmp_path: Path):
    """A symlinked *directory* inside the tree — the file-symlink test does
    not cover this: the escaping component is a path segment, not the leaf."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.xsd").write_text(_LEAK_XSD)
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside, root / "d", target_is_directory=True)

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("d/secret.xsd"))
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


def test_confinement_blocks_percent_encoded_traversal(tmp_path: Path):
    """``..%2F`` — percent-decoding must happen before the containment check,
    not after, or an encoded separator slips past a naive string comparison."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.xsd").write_text(_LEAK_XSD)
    root = tmp_path / "root"
    root.mkdir()

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("..%2Foutside%2Fsecret.xsd"))
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


def test_confinement_blocks_file_localhost_authority(tmp_path: Path):
    """``file://localhost/abs/path`` — the authority component must not be a
    way to smuggle an absolute path past the check."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.xsd"
    secret.write_text(_LEAK_XSD)
    root = tmp_path / "root"
    root.mkdir()

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing(f"file://localhost{secret}"))
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


def test_confinement_blocks_absolute_path_under_parse_wsdl_file(tmp_path: Path):
    """An absolute path with no traversal syntax at all.

    Distinct from the in-memory absolute-path test: there, local reads are
    refused outright; here they are permitted but must stay in the tree.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.xsd"
    secret.write_text(_LEAK_XSD)
    root = tmp_path / "root"
    root.mkdir()

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing(str(secret)))
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


def test_confinement_blocks_sibling_prefix_confusion(tmp_path: Path):
    """Root ``/x/root`` must not admit ``/x/root-evil``.

    A containment check written as a string prefix comparison passes this
    vector; a path-component comparison does not.
    """
    root = tmp_path / "root"
    root.mkdir()
    evil = tmp_path / "root-evil"
    evil.mkdir()
    (evil / "secret.xsd").write_text(_LEAK_XSD)

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("../root-evil/secret.xsd"))
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


def test_confinement_blocks_transitive_escape_from_subdirectory(tmp_path: Path):
    """Root WSDL -> in-tree subdirectory XSD -> out-of-tree XSD.

    The confinement root must stay pinned to the *root document's* directory
    as the chain descends, not drift to each importing file's own directory.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.xsd").write_text(_LEAK_XSD)
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "hop.xsd").write_text(
        '<?xml version="1.0"?>'
        '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:h">'
        '<xs:import namespace="urn:leak" schemaLocation="../../outside/secret.xsd"/>'
        "</xs:schema>"
    )

    wsdl = root / "t.wsdl"
    wsdl.write_bytes(
        _wsdl(types='<xsd:import namespace="urn:h" schemaLocation="sub/hop.xsd"/>')
    )
    with pytest.raises(ValueError, match=r"(?i)confin|outside|escape"):
        parse_wsdl_file(str(wsdl))


# --------------------------------------------------------------------------
# Positive tests. The guard must not be tightened into breaking these.
# Without them, over-tightening the confinement check keeps the suite green.
# --------------------------------------------------------------------------

_SIBLING_XSD = (
    '<?xml version="1.0"?>'
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:ok">'
    '<xs:complexType name="LegitType"><xs:sequence/></xs:complexType>'
    "</xs:schema>"
)


def _assert_imported(defn) -> None:
    assert "LegitType" in (getattr(defn, "complex_types", {}) or {}), (
        "a legitimate in-tree import was not resolved — the confinement "
        "guard is too strict"
    )


def test_sibling_import_still_resolves(tmp_path: Path):
    (tmp_path / "sib.xsd").write_text(_SIBLING_XSD)
    wsdl = tmp_path / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("sib.xsd"))
    _assert_imported(parse_wsdl_file(str(wsdl)))


def test_subdirectory_import_still_resolves(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.xsd").write_text(_SIBLING_XSD)
    wsdl = tmp_path / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("sub/deep.xsd"))
    _assert_imported(parse_wsdl_file(str(wsdl)))


def test_dotdot_that_stays_inside_the_tree_still_resolves(tmp_path: Path):
    """``a/../b/x.xsd`` contains traversal syntax but never leaves the tree.
    Rejecting on the presence of ``..`` rather than on the resolved location
    would break real multi-directory WSDL layouts."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "x.xsd").write_text(_SIBLING_XSD)
    wsdl = tmp_path / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("a/../b/x.xsd"))
    _assert_imported(parse_wsdl_file(str(wsdl)))


def test_absolute_file_uri_inside_the_tree_still_resolves(tmp_path: Path):
    target = tmp_path / "abs.xsd"
    target.write_text(_SIBLING_XSD)
    wsdl = tmp_path / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing(target.as_uri()))
    _assert_imported(parse_wsdl_file(str(wsdl)))


def test_in_tree_symlink_still_resolves(tmp_path: Path):
    """A symlink is not itself suspicious — only one whose target escapes."""
    (tmp_path / "real.xsd").write_text(_SIBLING_XSD)
    os.symlink(tmp_path / "real.xsd", tmp_path / "alias.xsd")
    wsdl = tmp_path / "t.wsdl"
    wsdl.write_bytes(_wsdl_importing("alias.xsd"))
    _assert_imported(parse_wsdl_file(str(wsdl)))
