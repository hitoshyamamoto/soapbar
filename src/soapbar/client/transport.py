# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""HTTP transport for SOAP client."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any


class HttpTransport:
    def __init__(self, timeout: float = 30.0, verify_ssl: bool = True) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        # Lazy long-lived httpx clients; created on first use, reused for
        # every subsequent request so TCP/TLS connections get pooled
        # (httpx.Client maintains an internal connection pool).
        # Call close()/aclose() or use the transport as a context manager
        # to release them.
        self._httpx_client: Any = None
        self._httpx_async_client: Any = None

    def _get_httpx_client(self) -> Any:
        """Return the lazy-initialized sync httpx.Client."""
        import httpx
        if self._httpx_client is None:
            self._httpx_client = httpx.Client(
                timeout=self.timeout, verify=self.verify_ssl
            )
        return self._httpx_client

    def _get_httpx_async_client(self) -> Any:
        """Return the lazy-initialized async httpx.AsyncClient."""
        import httpx
        if self._httpx_async_client is None:
            self._httpx_async_client = httpx.AsyncClient(
                timeout=self.timeout, verify=self.verify_ssl
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
            return self._send_httpx(url, body, headers)
        except ImportError:
            return self._send_urllib(url, body, headers)

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
        return resp.status_code, ct, content

    def fetch(self, url: str) -> bytes:
        """GET request for WSDL retrieval."""
        try:
            import httpx  # noqa: F401
            client = self._get_httpx_client()
            resp = client.get(url)
            resp.raise_for_status()
            return bytes(resp.content)
        except ImportError:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310
                return bytes(resp.read())
