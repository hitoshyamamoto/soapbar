"""Self-contained demo of the WS-Security N05 + N07 protections:

- **N05 — Timestamp expiry**: A ``wsu:Timestamp`` whose ``wsu:Expires`` is in
  the past is rejected by ``UsernameTokenValidator.validate``.
- **N07 — Nonce replay cache**: A ``PasswordDigest`` token reuses the same
  ``wsse:Nonce`` only once; the second time within the cache window the
  validator raises ``SecurityValidationError`` with "Nonce already used".

This demo runs entirely in-process (no HTTP server), so it's deterministic
and dependency-free beyond the dev group.

Run:
    uv run python examples/14_security_replay_protection/replay_demo.py
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from soapbar.core.envelope import SoapVersion
from soapbar.core.namespaces import NS
from soapbar.core.wssecurity import (
    SecurityValidationError,
    UsernameTokenCredential,
    UsernameTokenValidator,
    build_security_header,
)


class StaticValidator(UsernameTokenValidator):
    def get_password(self, username: str) -> str | None:
        return {"alice": "wonderland"}.get(username)


def main() -> None:
    validator = StaticValidator()

    print("--- N07: nonce replay protection")
    fixed_nonce = b"\x00" * 16
    fixed_created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    cred = UsernameTokenCredential(
        username="alice",
        password="wonderland",
        use_digest=True,
        nonce=fixed_nonce,
        created=fixed_created,
    )
    sec = build_security_header(cred, soap_ns=SoapVersion.SOAP_11.envelope_ns)

    print(f"  first call:  authenticated as {validator.validate(sec)!r}")
    try:
        # Build a fresh header with the same nonce to simulate a replay.
        sec_replay = build_security_header(cred, soap_ns=SoapVersion.SOAP_11.envelope_ns)
        validator.validate(sec_replay)
    except SecurityValidationError as e:
        print(f"  replay call: rejected — {e}")

    print("\n--- N05: expired Timestamp rejection")
    sec2 = build_security_header(
        UsernameTokenCredential("alice", "wonderland"),
        soap_ns=SoapVersion.SOAP_11.envelope_ns,
        timestamp_ttl=300,
    )
    # Force the Expires element into the past.
    ts = sec2.find(f"{{{NS.WSU}}}Timestamp")
    expires = ts.find(f"{{{NS.WSU}}}Expires")
    expires.text = (datetime.now(UTC) - timedelta(seconds=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    try:
        validator.validate(sec2)
    except SecurityValidationError as e:
        print(f"  expired Timestamp rejected — {e}")


if __name__ == "__main__":
    main()
