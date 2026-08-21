# Copyright 2026 Hitoshi Yamamoto
# SPDX-License-Identifier: Apache-2.0
"""Client DEBUG logging must not put credentials in a log.

Client logging (0.17.0, #193) writes whole envelopes to a log record. These
tests pin the properties that make that safe: silence unless opted in,
credentials redacted wherever they travel — the ``wsse:Security`` header *and*
the Body — non-XML bodies described rather than dumped, and a size ceiling.
"""
from __future__ import annotations

import logging

import pytest

from soapbar import SoapClient, UsernameTokenCredential
from soapbar.client._redaction import MAX_LOGGED_CHARS, redact_envelope
from soapbar.client.transport import HttpTransport
from soapbar.core.binding import OperationParameter, OperationSignature
from soapbar.core.types import xsd

CLIENT_LOGGER = "soapbar.client.client"
TRANSPORT_LOGGER = "soapbar.client.transport"

PASSWORD = "S3nh4-Sup3r-S3cr3t4"  # noqa: S105 — a canary, asserted to be absent

_OK_RESPONSE = (
    b'<?xml version="1.0"?>'
    b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<soapenv:Body><opResponse><result>7</result></opResponse></soapenv:Body>"
    b"</soapenv:Envelope>"
)


class _StubTransport(HttpTransport):
    """Returns a canned response without touching the network."""

    def __init__(self, response: bytes = _OK_RESPONSE, content_type: str = "text/xml") -> None:
        super().__init__()
        self._response = response
        self._content_type = content_type

    def send(
        self, url: str, body: bytes, headers: dict[str, str]
    ) -> tuple[int, str, bytes]:
        return 200, self._content_type, self._response


def _make_client(**kwargs: object) -> SoapClient:
    string_type = xsd.resolve("string")
    assert string_type is not None
    client = SoapClient.manual(
        "https://example.com/soap", transport=_StubTransport(), **kwargs  # type: ignore[arg-type]
    )
    client.register_operation(
        OperationSignature(
            name="op",
            input_params=[OperationParameter("Senha", string_type, required=False)],
            output_params=[OperationParameter("result", string_type, required=False)],
            soap_action="op",
        )
    )
    return client


class TestDebugLoggingIsOptIn:
    def test_silent_at_default_level(self, caplog: pytest.LogCaptureFixture) -> None:
        """Nothing is logged unless DEBUG is explicitly enabled."""
        caplog.set_level(logging.INFO)
        _make_client().call("op", Senha="x")
        assert [r for r in caplog.records if r.name.startswith("soapbar.client")] == []

    def test_request_envelope_logged_at_debug(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger=CLIENT_LOGGER)
        _make_client().call("op", Senha="x")
        messages = [r.getMessage() for r in caplog.records if r.name == CLIENT_LOGGER]
        assert any("Request envelope" in m for m in messages)


class TestCredentialsAreRedacted:
    def test_wsse_password_absent_from_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A real UsernameTokenCredential password never reaches a log record."""
        caplog.set_level(logging.DEBUG, logger=CLIENT_LOGGER)
        client = _make_client(
            wss_credential=UsernameTokenCredential(username="alice", password=PASSWORD)
        )
        client.call("op")
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert PASSWORD not in blob
        assert "redacted by soapbar" in blob

    def test_body_credential_absent_from_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A credential in the Body is redacted too.

        soapbar.contrib.ana's CotaOnline operations authenticate with
        Login/Senha as plain Body elements, so a wsse-only rule never sees them.
        """
        caplog.set_level(logging.DEBUG, logger=CLIENT_LOGGER)
        _make_client().call("op", Senha=PASSWORD)
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert PASSWORD not in blob
        assert "redacted by soapbar" in blob

    def test_response_is_redacted(self, caplog: pytest.LogCaptureFixture) -> None:
        """A wsse:Security header in the *response* is redacted as well."""
        signed = (
            b'<?xml version="1.0"?>'
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            b' xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/'
            b'oasis-200401-wss-wssecurity-secext-1.0.xsd">'
            b"<soapenv:Header><wsse:Security><wsse:UsernameToken>"
            b"<wsse:Password>" + PASSWORD.encode() + b"</wsse:Password>"
            b"</wsse:UsernameToken></wsse:Security></soapenv:Header>"
            b"<soapenv:Body><opResponse/></soapenv:Body></soapenv:Envelope>"
        )
        assert PASSWORD not in redact_envelope(signed)

    def test_username_is_kept(self) -> None:
        """Deliberate: a login is not a secret, and knowing which account was
        used is what makes a DEBUG log worth reading."""
        env = (
            b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<soapenv:Body><op><Login>alice</Login>"
            b"<Senha>" + PASSWORD.encode() + b"</Senha></op></soapenv:Body>"
            b"</soapenv:Envelope>"
        )
        out = redact_envelope(env)
        assert "alice" in out
        assert PASSWORD not in out


class TestRedactEnvelopeEdgeCases:
    def test_non_xml_body_is_described_not_dumped(self) -> None:
        """An MTOM multipart body embeds an envelope this function has not
        walked, so it must never be printed."""
        multipart = b"--boundary\r\nContent-Type: application/xop+xml\r\n\r\n" + b"x" * 400
        out = redact_envelope(multipart)
        assert "not parseable as XML" in out
        assert "xxxx" not in out
        assert str(len(multipart)) in out

    def test_large_body_is_truncated(self) -> None:
        payload = b"<a>" + b"z" * (MAX_LOGGED_CHARS * 2) + b"</a>"
        out = redact_envelope(payload)
        assert "truncated" in out
        assert len(out) < len(payload)

    def test_empty_body_does_not_raise(self) -> None:
        assert "not parseable as XML" in redact_envelope(b"")

    def test_envelope_without_secrets_is_returned_intact(self) -> None:
        env = b"<Envelope><Body><op><a>1</a></op></Body></Envelope>"
        out = redact_envelope(env)
        assert "<a>1</a>" in out
        assert "redacted by soapbar" not in out
