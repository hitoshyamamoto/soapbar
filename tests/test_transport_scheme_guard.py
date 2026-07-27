"""URL-scheme hardening for HttpTransport.

``urllib.request.urlopen`` dereferences ``file://`` / ``ftp://`` URLs, so a
request URL sourced from untrusted input could otherwise read local files.
``fetch()`` and ``_send_urllib()`` restrict the scheme to http(s); these tests
lock that guard in place.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from soapbar.client.transport import HttpTransport, _require_http_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/resource",
        "gopher://example.com/",
        "/etc/passwd",  # bare path: empty scheme
        "data:text/plain,hello",
    ],
)
def test_require_http_url_rejects_non_http_schemes(url: str) -> None:
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        _require_http_url(url)


@pytest.mark.parametrize(
    "url",
    ["http://example.com/svc.wsdl", "https://example.com/svc.wsdl", "HTTPS://EXAMPLE/x"],
)
def test_require_http_url_allows_http_schemes(url: str) -> None:
    # Scheme comparison is case-insensitive; no exception for http(s).
    _require_http_url(url)


def test_fetch_rejects_file_url_before_any_io() -> None:
    """A ``file://`` WSDL URL is rejected up front, before urllib is touched."""
    transport = HttpTransport()
    with (
        patch("urllib.request.urlopen") as urlopen,
        pytest.raises(ValueError, match="Unsupported URL scheme"),
    ):
        transport.fetch("file:///etc/passwd")
    urlopen.assert_not_called()


def test_send_urllib_rejects_file_url() -> None:
    transport = HttpTransport()
    with (
        patch("urllib.request.urlopen") as urlopen,
        pytest.raises(ValueError, match="Unsupported URL scheme"),
    ):
        transport._send_urllib("file:///etc/passwd", b"<body/>", {})
    urlopen.assert_not_called()
