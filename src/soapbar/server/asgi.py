"""ASGI adapter for SoapApplication."""
from __future__ import annotations

from typing import Any

from soapbar.server.application import SoapApplication


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

        if method == "GET" and "wsdl" in query_string.lower():
            wsdl = self.soap_app.get_wsdl()
            await self._send_response(send, 200, "text/xml; charset=utf-8", wsdl)
            return

        if method == "GET":
            body = b"soapbar SOAP endpoint - POST to invoke operations"
            await self._send_response(send, 200, "text/plain", body)
            return

        if method == "POST":
            # Read body
            body_chunks: list[bytes] = []
            while True:
                message = await receive()
                chunk = message.get("body", b"")
                if chunk:
                    body_chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body_bytes = b"".join(body_chunks)
            status, resp_ct, resp_body = self.soap_app.handle_request(
                body_bytes, soap_action=soap_action, content_type=content_type
            )
            await self._send_response(send, status, resp_ct, resp_body)
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
    ) -> None:
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode()),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
