# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""HTTP transport for SOAP client."""
from __future__ import annotations

import urllib.error
import urllib.request


class HttpTransport:
    def __init__(self, timeout: float = 30.0, verify_ssl: bool = True) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl

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
        import httpx
        verify = self.verify_ssl
        with httpx.Client(timeout=self.timeout, verify=verify) as client:
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
            import httpx
        except ImportError as err:
            raise RuntimeError(
                "httpx is required for async transport. Install soapbar[client]."
            ) from err

        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            resp = await client.post(url, content=body, headers=headers)
            ct = resp.headers.get("content-type", "text/xml")
            ct, content = self._decode_mtom_if_needed(ct, resp.content)
            return resp.status_code, ct, content

    def fetch(self, url: str) -> bytes:
        """GET request for WSDL retrieval."""
        try:
            import httpx
            with httpx.Client(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = client.get(url)
                resp.raise_for_status()
                return bytes(resp.content)
        except ImportError:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310
                return bytes(resp.read())
