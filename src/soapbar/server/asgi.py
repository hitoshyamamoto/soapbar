# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""ASGI adapter for SoapApplication."""
from __future__ import annotations

from typing import Any

from soapbar.server.application import SoapApplication


def _is_mtom(content_type: str) -> bool:
    ct = content_type.lower()
    return "multipart/related" in ct and "application/xop+xml" in ct


class AsgiSoapApp:
    def __init__(self, soap_app: SoapApplication) -> None:
        self.soap_app = soap_app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        scope_type = scope.get("type", "")

        if scope_type == "lifespan":
            await self._handle_lifespan(receive, send)
            return

        if scope_type != "http":
            return

        method = scope.get("method", "GET").upper()
        query_string = scope.get("query_string", b"").decode()
        headers_raw: list[tuple[bytes, bytes]] = scope.get("headers", [])

        headers = {k.lower(): v for k, v in headers_raw}
        content_type = headers.get(b"content-type", b"text/xml").decode()
        soap_action_raw = headers.get(b"soapaction", b"")
        soap_action = soap_action_raw.decode().strip('"') if soap_action_raw else ""
        accept = headers.get(b"accept", b"").decode()

        if method == "GET" and "wsdl" in query_string.lower():
            # X06 — WSDL access control
            _req_headers = {
                k.decode(errors="replace"): v.decode(errors="replace")
                for k, v in scope.get("headers", [])
            }
            if not self.soap_app.check_wsdl_access(_req_headers):
                await self._send_response(send, 403, "text/plain", b"WSDL access denied")
                return
            wsdl = self.soap_app.get_wsdl()
            await self._send_response(send, 200, "text/xml; charset=utf-8", wsdl)
            return

        if method == "POST":
            from soapbar.core.xml import BodyTooLargeError
            max_size = self.soap_app.max_body_size
            # Read body with a running cap: stop buffering as soon as the total
            # exceeds the limit, so a multi-gigabyte streamed POST cannot exhaust
            # memory before the size check in handle_request runs.
            body_chunks: list[bytes] = []
            total = 0
            oversize = False
            while True:
                message = await receive()
                chunk = message.get("body", b"")
                if chunk:
                    total += len(chunk)
                    if total > max_size:
                        oversize = True
                        break
                    body_chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body_bytes = b"".join(body_chunks)

            # C2 — HTTP-level gzip (opt-in). Bounded to reject a decompression
            # bomb before it inflates in memory.
            if not oversize and self.soap_app.enable_gzip:
                from soapbar.server._compression import decompress_if_gzipped
                content_encoding = headers.get(b"content-encoding", b"").decode()
                try:
                    body_bytes = decompress_if_gzipped(
                        body_bytes, content_encoding, max_size
                    )
                except BodyTooLargeError:
                    oversize = True

            # Decode MTOM/XOP into plain XML before dispatch (bounded against
            # XOP amplification).
            if not oversize and _is_mtom(content_type):
                from soapbar.core.mtom import parse_mtom
                try:
                    mtom_msg = parse_mtom(body_bytes, content_type, max_size)
                    body_bytes = mtom_msg.soap_xml
                    # Adjust content_type so handle_request sees plain SOAP
                    content_type = (
                        "application/soap+xml; charset=utf-8"
                        if "soap+xml" in content_type
                        else "text/xml; charset=utf-8"
                    )
                except BodyTooLargeError:
                    oversize = True

            status, resp_ct, resp_body = self.soap_app.handle_request(
                b"" if oversize else body_bytes,
                soap_action=soap_action,
                content_type=content_type,
                accept_header=accept,
                _force_oversize=oversize,
            )
            # C2 — compress outbound if Accept-Encoding advertised gzip.
            resp_content_encoding: str | None = None
            if self.soap_app.enable_gzip:
                from soapbar.server._compression import compress_response
                accept_encoding = headers.get(b"accept-encoding", b"").decode()
                resp_body, resp_content_encoding = compress_response(
                    resp_body, accept_encoding
                )
            await self._send_response(
                send, status, resp_ct, resp_body, resp_content_encoding
            )
            return

        # Other methods → 405
        await self._send_response(send, 405, "text/plain", b"Method Not Allowed")

    async def _handle_lifespan(self, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _send_response(
        self,
        send: Any,
        status: int,
        content_type: str,
        body: bytes,
        content_encoding: str | None = None,
    ) -> None:
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", content_type.encode()),
            (b"content-length", str(len(body)).encode()),
        ]
        if content_encoding:
            headers.append((b"content-encoding", content_encoding.encode()))
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
