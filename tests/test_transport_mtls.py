"""Mutual-TLS coverage for HttpTransport: a real localhost handshake that
requires a client certificate, plus the PKCS#12 → PEM helper.

Skipped automatically when httpx or cryptography are not installed.
"""
from __future__ import annotations

import datetime
import http.server
import ipaddress
import ssl
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from soapbar.client.transport import HttpTransport, load_pkcs12

httpx = pytest.importorskip("httpx")
crypto = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


# ---------------------------------------------------------------------------
# Tiny CA + certificate factory
# ---------------------------------------------------------------------------
def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(
    cn: str,
    subject_key: rsa.RSAPrivateKey,
    issuer_cn: str,
    issuer_key: rsa.RSAPrivateKey,
    *,
    is_ca: bool,
    san: list[x509.GeneralName] | None = None,
) -> x509.Certificate:
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _write(path: Path, *pems: bytes) -> str:
    path.write_bytes(b"".join(pems))
    return str(path)


class _PKI:
    """A CA plus server and client leaf certs, materialised as PEM files."""

    def __init__(self, root: Path) -> None:
        ca_key = _key()
        ca = _cert("soapbar-test-ca", ca_key, "soapbar-test-ca", ca_key, is_ca=True)

        # SAN covers both names we might dial (localhost and 127.0.0.1).
        srv_key = _key()
        srv = _cert(
            "localhost", srv_key, "soapbar-test-ca", ca_key, is_ca=False,
            san=[
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ],
        )

        cli_key = _key()
        cli = _cert("soapbar-test-client", cli_key, "soapbar-test-ca", ca_key, is_ca=False)

        pem = serialization.Encoding.PEM
        nokey = serialization.NoEncryption()
        p8 = serialization.PrivateFormat.PKCS8
        trad = serialization.PrivateFormat.TraditionalOpenSSL

        self.ca_file = _write(root / "ca.pem", ca.public_bytes(pem))
        self.server_cert = _write(root / "server.pem", srv.public_bytes(pem))
        self.server_key = _write(root / "server.key", srv_key.private_bytes(pem, trad, nokey))
        self.client_cert = _write(root / "client.pem", cli.public_bytes(pem))
        self.client_key = _write(root / "client.key", cli_key.private_bytes(pem, p8, nokey))

        # A PKCS#12 bundle of the client identity (+ CA as a chain extra).
        self.pfx = root / "client.pfx"
        self.pfx.write_bytes(
            pkcs12.serialize_key_and_certificates(
                b"client", cli_key, cli, [ca], serialization.BestAvailableEncryption(b"secret")
            )
        )


class _Handler(http.server.BaseHTTPRequestHandler):
    def _ok(self) -> None:
        body = b"<ok/>"
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._ok()

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._ok()

    def log_message(self, *_args: object) -> None:
        pass  # keep test output quiet


@pytest.fixture
def mtls_server(tmp_path: Path) -> Iterator[tuple[str, _PKI]]:
    pki = _PKI(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki.server_cert, pki.server_key)
    ctx.load_verify_locations(pki.ca_file)
    ctx.verify_mode = ssl.CERT_REQUIRED  # demand a client certificate

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{port}/", pki
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Handshake tests
# ---------------------------------------------------------------------------
def test_mtls_success_with_file_cert(mtls_server: tuple[str, _PKI]) -> None:
    url, pki = mtls_server
    transport = HttpTransport(
        client_cert=(pki.client_cert, pki.client_key), ca_bundle=pki.ca_file
    )
    try:
        assert transport.fetch(url) == b"<ok/>"
    finally:
        transport.close()


def test_mtls_success_with_in_memory_pem(mtls_server: tuple[str, _PKI]) -> None:
    url, pki = mtls_server
    cert_pem, key_pem = load_pkcs12(str(pki.pfx), "secret")
    transport = HttpTransport(client_cert=(cert_pem, key_pem), ca_bundle=pki.ca_file)
    try:
        assert transport.fetch(url) == b"<ok/>"
    finally:
        transport.close()


def test_mtls_rejected_without_client_cert(mtls_server: tuple[str, _PKI]) -> None:
    url, pki = mtls_server
    # Server verifies, but we present no client certificate → handshake fails.
    transport = HttpTransport(ca_bundle=pki.ca_file)
    try:
        with pytest.raises(httpx.TransportError):
            transport.fetch(url)
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# load_pkcs12 + guard
# ---------------------------------------------------------------------------
def test_load_pkcs12_returns_chain_and_key(tmp_path: Path) -> None:
    pki = _PKI(tmp_path)
    cert_pem, key_pem = load_pkcs12(str(pki.pfx), "secret")
    # End-entity cert + the CA chain extra are both present.
    assert cert_pem.count(b"BEGIN CERTIFICATE") == 2
    assert b"BEGIN PRIVATE KEY" in key_pem
    # The PEM re-parses, leaf-first, to the client subject.
    marker = b"-----END CERTIFICATE-----\n"
    leaf_pem = cert_pem.split(marker)[0] + marker
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    assert leaf.subject.rfc4514_string() == "CN=soapbar-test-client"


def test_load_pkcs12_rejects_password_mismatch(tmp_path: Path) -> None:
    pki = _PKI(tmp_path)
    with pytest.raises(ValueError):
        load_pkcs12(str(pki.pfx), "wrong-password")


def test_mtls_without_httpx_raises_clear_error() -> None:
    transport = HttpTransport(ca_bundle="/nonexistent/ca.pem")
    with patch.dict(sys.modules, {"httpx": None}), pytest.raises(RuntimeError, match="httpx"):
        transport.fetch("https://example.invalid/")


def test_send_mtls_without_httpx_raises_clear_error() -> None:
    transport = HttpTransport(client_cert=("client.pem", "client.key"))
    with patch.dict(sys.modules, {"httpx": None}), pytest.raises(RuntimeError, match="httpx"):
        transport.send("https://example.invalid/", b"<r/>", {})


def test_build_context_from_combined_pem_path(tmp_path: Path) -> None:
    pki = _PKI(tmp_path)
    combined = tmp_path / "combined.pem"
    combined.write_bytes(Path(pki.client_cert).read_bytes() + Path(pki.client_key).read_bytes())
    ctx = HttpTransport(client_cert=str(combined), ca_bundle=pki.ca_file)._verify_arg()
    assert isinstance(ctx, ssl.SSLContext)


def test_build_context_insecure_disables_verification(tmp_path: Path) -> None:
    pki = _PKI(tmp_path)
    ctx = HttpTransport(
        verify_ssl=False, client_cert=(pki.client_cert, pki.client_key)
    )._verify_arg()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_no_tls_config_keeps_boolean_verify() -> None:
    # Plain transport: no SSLContext is built; httpx gets the boolean default.
    assert HttpTransport()._verify_arg() is True
