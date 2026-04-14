"""WSS UsernameToken client — sends a PasswordDigest credential.

``use_digest=True`` hashes the password with the nonce and timestamp per
OASIS WSS UsernameToken Profile 1.0 §3.2.1.  PasswordDigest does NOT
encrypt the traffic — it merely avoids sending the password in plaintext —
so production deployments should still use TLS.

Run:
    uv run python examples/06_username_token_auth/server.py &
    uv run python examples/06_username_token_auth/client.py
"""
from __future__ import annotations

from soapbar.client.client import SoapClient
from soapbar.core.fault import SoapFault
from soapbar.core.wssecurity import UsernameTokenCredential


def call(credential: UsernameTokenCredential, who: str) -> None:
    client = SoapClient(
        wsdl_url="http://127.0.0.1:8006/soap?wsdl",
        wss_credential=credential,
    )
    try:
        reply = client.call("hello", who=who)
        print(f"  {credential.username:>6} → {reply}")
    except SoapFault as fault:
        print(f"  {credential.username:>6} → Fault: {fault.faultstring}")


def main() -> None:
    print("PasswordDigest UsernameToken demo")
    print("-" * 40)

    call(UsernameTokenCredential("alice", "wonderland", use_digest=True), "world")
    call(UsernameTokenCredential("bob",   "builder",    use_digest=True), "there")

    # Wrong password — the validator rejects the digest and the server
    # returns a SOAP Fault.
    call(UsernameTokenCredential("alice", "not-the-password", use_digest=True), "world")


if __name__ == "__main__":
    main()
