"""WS-Security 1.0 UsernameToken support (OASIS WSS 2004).

Implements:
- PasswordText (plain-text password in wsse:Password)
- PasswordDigest (SHA-1 digest per WSS 1.0 §3.2.1)

G09: WS-Security UsernameToken credential building and validation.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime

from lxml.etree import _Element

from soapbar.core.namespaces import NS
from soapbar.core.xml import make_element, sub_element

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PasswordText = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
)
_PasswordDigest = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
)
_Base64Binary = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------

@dataclass
class UsernameTokenCredential:
    """Holds the username and password for a WS-Security UsernameToken.

    Args:
        username: The username to embed.
        password: The plain-text password.
        use_digest: If True, the password is hashed via PasswordDigest
            (SHA-1 based, per WSS 1.0 §3.2.1).  If False (default),
            PasswordText is used.
        nonce: Override the random nonce bytes (mainly for testing).
        created: Override the creation timestamp string (mainly for testing).
    """
    username: str
    password: str
    use_digest: bool = False
    nonce: bytes | None = field(default=None, repr=False)
    created: str | None = None


# ---------------------------------------------------------------------------
# Digest helper
# ---------------------------------------------------------------------------

def _digest_password(nonce_bytes: bytes, created: str, password: str) -> str:
    """Compute PasswordDigest = Base64(SHA-1(nonce + created + password)).

    Per OASIS WSS UsernameToken Profile 1.0 §3.2.1.
    """
    raw = nonce_bytes + created.encode("utf-8") + password.encode("utf-8")
    return base64.b64encode(hashlib.sha1(raw).digest()).decode("ascii")  # noqa: S324


# ---------------------------------------------------------------------------
# Security header builder
# ---------------------------------------------------------------------------

def build_security_header(credential: UsernameTokenCredential) -> _Element:
    """Build a ``wsse:Security`` header element for *credential*.

    Returns a ``wsse:Security`` element ready to be added as a SOAP header.
    The element is *not* marked ``mustUnderstand`` by default; callers may
    set that attribute if required.
    """
    wsse_ns = NS.WSSE
    wsu_ns = NS.WSU
    nsmap: dict[str | None, str] = {"wsse": wsse_ns, "wsu": wsu_ns}

    security = make_element(f"{{{wsse_ns}}}Security", nsmap=nsmap)

    token = sub_element(security, f"{{{wsse_ns}}}UsernameToken")
    sub_element(token, f"{{{wsse_ns}}}Username", text=credential.username)

    if credential.use_digest:
        nonce_bytes = credential.nonce if credential.nonce is not None else secrets.token_bytes(16)
        created = credential.created or datetime.now(UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        digest = _digest_password(nonce_bytes, created, credential.password)

        pw_elem = sub_element(
            token,
            f"{{{wsse_ns}}}Password",
            attrib={"Type": _PasswordDigest},
            text=digest,
        )
        _ = pw_elem  # used via sub_element side-effect

        nonce_elem = sub_element(
            token,
            f"{{{wsse_ns}}}Nonce",
            attrib={"EncodingType": _Base64Binary},
            text=base64.b64encode(nonce_bytes).decode("ascii"),
        )
        _ = nonce_elem

        created_elem = sub_element(token, f"{{{wsu_ns}}}Created", text=created)
        _ = created_elem
    else:
        sub_element(
            token,
            f"{{{wsse_ns}}}Password",
            attrib={"Type": _PasswordText},
            text=credential.password,
        )

    return security


# ---------------------------------------------------------------------------
# Validation interface
# ---------------------------------------------------------------------------

class SecurityValidationError(Exception):
    """Raised by UsernameTokenValidator when authentication fails."""


class UsernameTokenValidator(ABC):
    """Abstract base class for server-side UsernameToken validation.

    Subclass and implement :meth:`get_password` to look up the expected
    password for a given username.  The base class handles digest verification
    and raises :class:`SecurityValidationError` on failure.
    """

    @abstractmethod
    def get_password(self, username: str) -> str | None:
        """Return the plain-text password for *username*, or None if unknown."""

    def validate(self, security_element: _Element) -> str:
        """Validate a ``wsse:Security`` element and return the authenticated username.

        Raises:
            SecurityValidationError: if authentication fails.
        """
        wsse_ns = NS.WSSE
        wsu_ns = NS.WSU

        token = security_element.find(f"{{{wsse_ns}}}UsernameToken")
        if token is None:
            raise SecurityValidationError("Missing wsse:UsernameToken")

        username_elem = token.find(f"{{{wsse_ns}}}Username")
        if username_elem is None or not username_elem.text:
            raise SecurityValidationError("Missing wsse:Username")
        username = username_elem.text

        password_elem = token.find(f"{{{wsse_ns}}}Password")
        if password_elem is None:
            raise SecurityValidationError("Missing wsse:Password")

        expected = self.get_password(username)
        if expected is None:
            raise SecurityValidationError(f"Unknown username: {username!r}")

        pw_type = password_elem.get("Type", _PasswordText)
        provided = password_elem.text or ""

        if pw_type == _PasswordDigest:
            nonce_elem = token.find(f"{{{wsse_ns}}}Nonce")
            created_elem = token.find(f"{{{wsu_ns}}}Created")
            if nonce_elem is None or created_elem is None:
                raise SecurityValidationError(
                    "PasswordDigest requires wsse:Nonce and wsu:Created"
                )
            try:
                nonce_bytes = base64.b64decode(nonce_elem.text or "")
            except Exception as exc:
                raise SecurityValidationError("Invalid Nonce encoding") from exc
            created = created_elem.text or ""
            expected_digest = _digest_password(nonce_bytes, created, expected)
            if not secrets.compare_digest(provided, expected_digest):
                raise SecurityValidationError("PasswordDigest mismatch")
        else:
            # PasswordText or any other type: compare plaintext
            if not secrets.compare_digest(provided, expected):
                raise SecurityValidationError("Password mismatch")

        return username


__all__ = [
    "SecurityValidationError",
    "UsernameTokenCredential",
    "UsernameTokenValidator",
    "build_security_header",
]
