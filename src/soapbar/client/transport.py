# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""HTTP transport for SOAP client."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Union

# A client certificate may be given as httpx-native file paths (a single
# combined PEM, or a ``(certfile, keyfile)`` / ``(certfile, keyfile, password)``
# tuple), or as in-memory PEM bytes ``(cert_pem, key_pem)`` — typically the
# output of :func:`load_pkcs12`, which never touches the disk.
ClientCert = Union[str, "tuple[str, str]", "tuple[str, str, str]", "tuple[bytes, bytes]", None]


class HttpTransport:
    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        client_cert: ClientCert = None,
        ca_bundle: str | None = None,
        persist_cookies: bool = True,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        # Mutual TLS: present *client_cert* on the handshake. ``ca_bundle`` is a
        # path to a custom CA bundle used to verify the server (e.g. a private
        # or government PKI root); when set it takes precedence over the
        # boolean ``verify_ssl``. Both require httpx (the urllib fallback cannot
        # carry a client certificate).
        self.client_cert = client_cert
        self.ca_bundle = ca_bundle
        # Session cookies. The pooled httpx client keeps a cookie jar across
        # calls, so a ``Set-Cookie`` from one SOAP call (e.g. a login that
        # returns JSESSIONID) is sent on the next — the basis for stateful
        # services like IRS MeF. Set ``persist_cookies=False`` for stateless
        # behaviour (the jar is cleared after every call). Read or inject
        # cookies via the :attr:`cookies` jar.
        self.persist_cookies = persist_cookies
        # Lazy long-lived httpx clients; created on first use, reused for
        # every subsequent request so TCP/TLS connections get pooled
        # (httpx.Client maintains an internal connection pool).
        # Call close()/aclose() or use the transport as a context manager
        # to release them.
        self._httpx_client: Any = None
        self._httpx_async_client: Any = None
        self._ssl_context: Any = None  # built once for in-memory PEM client certs

    def _mtls_requested(self) -> bool:
        return self.client_cert is not None or self.ca_bundle is not None

    @property
    def cookies(self) -> Any:
        """The live ``httpx.Cookies`` jar this transport carries across calls.

        Read a session cookie after a call (``transport.cookies.get("JSESSIONID")``)
        or inject one before (``transport.cookies.set("sid", "...", domain=...)``).
        Backed by the pooled sync client, so it persists for the session.
        Requires httpx.
        """
        return self._get_httpx_client().cookies

    def _clear_cookies_if_stateless(self, client: Any) -> None:
        if not self.persist_cookies:
            client.cookies.clear()

    def _verify_arg(self) -> Any:
        """Return the value to pass as httpx ``verify``.

        Any mutual-TLS or custom-CA configuration is expressed as an
        ``ssl.SSLContext`` (modern httpx deprecated ``verify=<path>`` and the
        ``cert=`` shortcut). The plain case keeps the boolean default.
        """
        if not self._mtls_requested():
            return self.verify_ssl
        return self._build_ssl_context()

    def _build_ssl_context(self) -> Any:
        """Build (and cache) an SSLContext trusting the configured CA and, when
        set, presenting the client certificate."""
        if self._ssl_context is not None:
            return self._ssl_context
        import ssl

        if self.ca_bundle is not None:
            ctx = ssl.create_default_context(cafile=self.ca_bundle)
        else:
            ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if self.client_cert is not None:
            self._load_client_cert(ctx, self.client_cert)
        self._ssl_context = ctx
        return ctx

    @staticmethod
    def _load_client_cert(ctx: Any, cert: ClientCert) -> None:
        """Load *cert* into *ctx*, accepting file paths or in-memory PEM bytes.

        In-memory PEM is written to a transient ``0600`` temp file only for the
        duration of ``load_cert_chain`` — OpenSSL copies the material into the
        context, so the file is unlinked immediately and the key never persists.
        """
        if isinstance(cert, tuple) and cert and isinstance(cert[0], (bytes, bytearray)):
            import os
            import tempfile

            cert_pem, key_pem = cert
            fd, path = tempfile.mkstemp(suffix=".pem")  # 0600 by default
            try:
                os.write(fd, cert_pem + b"\n" + key_pem)
                os.close(fd)
                ctx.load_cert_chain(path)
            finally:
                os.unlink(path)
        elif isinstance(cert, str):
            ctx.load_cert_chain(cert)  # single combined-PEM path
        elif isinstance(cert, tuple):
            certfile = cert[0]
            keyfile = cert[1] if len(cert) > 1 else None
            password = cert[2] if len(cert) > 2 else None
            ctx.load_cert_chain(certfile, keyfile, password)

    def _get_httpx_client(self) -> Any:
        """Return the lazy-initialized sync httpx.Client."""
        import httpx
        if self._httpx_client is None:
            self._httpx_client = httpx.Client(
                timeout=self.timeout, verify=self._verify_arg(), follow_redirects=True
            )
        return self._httpx_client

    def _get_httpx_async_client(self) -> Any:
        """Return the lazy-initialized async httpx.AsyncClient."""
        import httpx
        if self._httpx_async_client is None:
            self._httpx_async_client = httpx.AsyncClient(
                timeout=self.timeout, verify=self._verify_arg(), follow_redirects=True
            )
        return self._httpx_async_client

    def close(self) -> None:
        """Close the long-lived sync httpx.Client, if any. Safe to call
        multiple times; no-op when httpx is not installed or the client
        has never been created."""
        if self._httpx_client is not None:
            self._httpx_client.close()
            self._httpx_client = None

    async def aclose(self) -> None:
        """Close the long-lived async httpx.AsyncClient, if any."""
        if self._httpx_async_client is not None:
            await self._httpx_async_client.aclose()
            self._httpx_async_client = None

    def __enter__(self) -> HttpTransport:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def send(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        """Send SOAP request. Returns (status, content_type, body)."""
        try:
            import httpx as _httpx  # noqa: F401
        except ImportError:
            if self._mtls_requested():
                raise RuntimeError(
                    "Client certificate / custom CA bundle require httpx. "
                    "Install soapbar[client]."
                ) from None
            return self._send_urllib(url, body, headers)
        return self._send_httpx(url, body, headers)

    @staticmethod
    def _decode_mtom_if_needed(ct: str, body: bytes) -> tuple[str, bytes]:
        """If *body* is an MTOM multipart response, resolve XOP includes and
        return the plain SOAP XML with a normalised content-type.  Otherwise
        pass through unchanged."""
        ct_lower = ct.lower()
        if "multipart/related" in ct_lower and "application/xop+xml" in ct_lower:
            from soapbar.core.mtom import parse_mtom
            mtom_msg = parse_mtom(body, ct)
            normalised_ct = (
                "application/soap+xml; charset=utf-8"
                if "soap+xml" in ct_lower
                else "text/xml; charset=utf-8"
            )
            return normalised_ct, mtom_msg.soap_xml
        return ct, body

    def _send_httpx(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        client = self._get_httpx_client()
        resp = client.post(url, content=body, headers=headers)
        ct = resp.headers.get("content-type", "text/xml")
        ct, content = self._decode_mtom_if_needed(ct, resp.content)
        self._clear_cookies_if_stateless(client)
        return resp.status_code, ct, content

    def _send_urllib(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                ct = resp.headers.get("Content-Type", "text/xml")
                raw = resp.read()
                ct, raw = self._decode_mtom_if_needed(ct, raw)
                return resp.status, ct, raw
        except urllib.error.HTTPError as e:
            ct = e.headers.get("Content-Type", "text/xml")
            return e.code, ct, e.read()

    async def send_async(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
    ) -> tuple[int, str, bytes]:
        """Send async SOAP request. Requires httpx."""
        try:
            import httpx  # noqa: F401
        except ImportError as err:
            raise RuntimeError(
                "httpx is required for async transport. Install soapbar[client]."
            ) from err

        client = self._get_httpx_async_client()
        resp = await client.post(url, content=body, headers=headers)
        ct = resp.headers.get("content-type", "text/xml")
        ct, content = self._decode_mtom_if_needed(ct, resp.content)
        self._clear_cookies_if_stateless(client)
        return resp.status_code, ct, content

    def fetch(self, url: str) -> bytes:
        """GET request for WSDL retrieval."""
        try:
            import httpx  # noqa: F401
        except ImportError:
            if self._mtls_requested():
                raise RuntimeError(
                    "Client certificate / custom CA bundle require httpx. "
                    "Install soapbar[client]."
                ) from None
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310
                return bytes(resp.read())
        client = self._get_httpx_client()
        resp = client.get(url)
        resp.raise_for_status()
        return bytes(resp.content)


def load_pkcs12(path: str, password: str | None = None) -> tuple[bytes, bytes]:
    """Load a PKCS#12 (``.pfx`` / ``.p12``) bundle into PEM bytes.

    Returns ``(cert_pem, key_pem)`` where ``cert_pem`` is the full certificate
    chain (end-entity certificate first, followed by any bundled intermediates)
    and ``key_pem`` is the unencrypted PKCS#8 private key. Both are held in
    memory only — the key is never written to disk or logged. Feed the result
    straight to :class:`HttpTransport`::

        cert_pem, key_pem = load_pkcs12("cert.pfx", "password")
        transport = HttpTransport(client_cert=(cert_pem, key_pem), ca_bundle="ca.pem")

    Typical use is an ICP-Brasil A1 certificate for SEFAZ NF-e. A3 (hardware
    token) certificates are out of scope. Requires the ``cryptography`` package
    (install ``soapbar[security]``).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    pw = password.encode() if isinstance(password, str) else password
    with open(path, "rb") as handle:
        data = handle.read()

    key, cert, additional = pkcs12.load_key_and_certificates(data, pw)
    if cert is None or key is None:
        raise ValueError("PKCS#12 bundle is missing a certificate or private key")

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    for extra in additional or ():
        cert_pem += extra.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem
