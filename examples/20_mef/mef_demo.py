"""
examples/20_mef/mef_demo.py — Consume the IRS Modernized e-File (MeF) A2A web service with soapbar.

PREREQUISITES (external — cannot be bypassed in code)
    Running this needs IRS enrollment: ETIN + EFIN, a registered A2A System ID,
    and the A2A Toolkit (SDK) — obtained by emailing the IRS MeF mailbox — which
    ships the actual WSDL and operation names. The two soapbar core features it
    relies on are now available:
      * mutual TLS — HttpTransport(client_cert=...) for the Strong Auth cert
      * session cookies — HttpTransport(persist_cookies=True) carries JSESSIONID + dc
    `main()` does not hit the network; it prints guidance. Provide a real
    certificate + toolkit WSDL + credentials and call `run_session()`.

WHAT THIS DEMONSTRATES
    A session-based government SOAP/HTTP service: log in, carry the session
    cookies on each call, submit returns (as MTOM attachments), poll status, and
    log out. soapbar supports MTOM, persistent session cookies, and mTLS.

SERVICE FACTS (verified against IRS "Portal Transition Guide for Modernized
e-File (MeF)" and IRS Publications 1436 / 4163 / 4164, plus the public MeF
schema pages on irs.gov for tax year 2026)
    Protocol     : SOAP/HTTP web service (Application-to-Application, "A2A").
    Session      : the Login Service Request returns JSESSIONID (server
                   stickiness) and a `dc` cookie; both MUST be echoed on every
                   subsequent request within the session.
    Security     : Strong Authentication client certificates are required for
                   transmission.
    Enrollment   : transmitters need ETIN + EFIN; A2A users register their system
                   to obtain a System ID; the A2A Toolkit is requested by email.
    Payloads     : returns are XML per IRS-approved schemas (public on irs.gov),
                   typically carried as MTOM attachments.

REQUIREMENTS
    soapbar[client], the A2A Toolkit WSDL, a Strong Authentication certificate,
    and valid IRS credentials. Without these, this remains a reference only.

Run:
    uv run python examples/20_mef/mef_demo.py
"""

from __future__ import annotations

from soapbar import HttpTransport, SoapClient, SoapFault

# --- configuration (edit these; never commit real credentials/certs) -------
MEF_ENDPOINT = "https://la.www4.irs.gov/..."  # from the A2A Toolkit
CLIENT_CERT_PEM = "/path/to/strong-auth-cert.pem"
CLIENT_KEY_PEM = "/path/to/strong-auth-key.pem"
A2A_WSDL = "/path/to/a2a-toolkit/MeFHeaderService.wsdl"  # shipped in the toolkit


def build_transport() -> HttpTransport:
    """mTLS (Strong Authentication cert) + persistent session cookies.

    Uses features 1.1 and 1.2: the client certificate is presented on the
    handshake, and the cookie jar carries JSESSIONID + dc across the
    Login → call → Logout sequence automatically.
    """
    return HttpTransport(
        client_cert=(CLIENT_CERT_PEM, CLIENT_KEY_PEM),
        persist_cookies=True,
    )


def run_session() -> None:
    """Login -> (submit / poll) -> Logout, with cookies carried automatically."""
    transport = build_transport()
    client = SoapClient(wsdl_url=A2A_WSDL, transport=transport)

    try:
        # 1) Login. The response sets JSESSIONID + dc cookies; with
        #    persist_cookies=True they are reused on every later call.
        login = client.call("Login")  # exact op name comes from the toolkit WSDL
        print("Login result:", str(login)[:200])
        print("Session cookie:", transport.cookies.get("JSESSIONID"))

        # 2) Submit returns as MTOM attachments (soapbar supports MTOM today).
        #    mtom_client = SoapClient(wsdl_url=A2A_WSDL, transport=transport, use_mtom=True)
        #    cid = mtom_client.add_attachment(return_zip_bytes, content_type="application/zip")
        #    mtom_client.call("SendSubmissions", ...)

        # 3) Poll acknowledgements / status.
        #    client.call("GetNewSubmissionsStatus", ...)
        #    client.call("GetAcks", ...)

    except SoapFault as fault:
        print(f"SOAP fault: {fault.faultcode} / {fault.faultstring}")
        return
    finally:
        # 4) Always log out to release the session.
        try:
            client.call("Logout")
        except Exception:
            pass


def main() -> None:
    print("IRS MeF A2A reference example.")
    print(
        "soapbar's mTLS (Strong Auth cert) and session-cookie persistence "
        "(JSESSIONID + dc) are ready. Configure CLIENT_CERT_PEM / CLIENT_KEY_PEM "
        "and the A2A Toolkit WSDL, and complete IRS enrollment (ETIN/EFIN, "
        "System ID, A2A Toolkit), then call run_session()."
    )
    # run_session()  # enable once prerequisites are met


if __name__ == "__main__":
    main()
