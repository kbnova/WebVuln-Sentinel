
import socket
from types import SimpleNamespace

import pytest

import app.scanner as scanner

from app.scanner import (
    create_http_session,
    scan_website,
    validate_url,
)


# --------------------------------------------------
# URL Validation Tests
# --------------------------------------------------

def test_validate_url_rejects_invalid_url():
    result = validate_url("not-a-url", {})

    assert result[0] is False


def test_validate_url_rejects_non_http_scheme():
    result = validate_url("ftp://example.com", {})

    assert result[0] is False


def test_validate_url_rejects_localhost(monkeypatch):
    scope = {
        "authorized_domains": ["localhost"],
        "allow_subdomains": False,
    }

    monkeypatch.setattr(
        scanner,
        "is_public_host",
        lambda hostname: False,
    )

    result = validate_url("http://localhost", scope)

    assert result[0] is False


def test_validate_url_rejects_private_ip():
    scope = {
        "authorized_domains": ["192.168.1.1"],
        "allow_subdomains": False,
    }

    result = validate_url("http://192.168.1.1", scope)

    assert result[0] is False


# --------------------------------------------------
# HTTP Session Tests
# --------------------------------------------------

def test_create_http_session_disables_environment_proxies():
    session = create_http_session()

    try:
        assert session.trust_env is False
    finally:
        session.close()


def test_create_http_session_uses_pinned_ip_adapter():
    session = create_http_session()

    try:
        http_adapter = session.get_adapter("http://example.com")
        https_adapter = session.get_adapter("https://example.com")

        assert isinstance(http_adapter, scanner.PinnedIPAdapter)
        assert isinstance(https_adapter, scanner.PinnedIPAdapter)
    finally:
        session.close()


# --------------------------------------------------
# DNS Pinning Test
# --------------------------------------------------

def test_http_adapter_pins_connection_to_validated_ip(monkeypatch):
    session = create_http_session()

    try:
        # Mock DNS to return a public IP.
        monkeypatch.setattr(
            scanner.socket,
            "getaddrinfo",
            lambda *args, **kwargs: [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("93.184.216.34", 443),
                )
            ],
        )

        connected_address = {}

        # Mock the socket connection to avoid real network access.
        def fake_create_connection(
            address,
            timeout,
            source_address=None,
            socket_options=None,
        ):
            connected_address["address"] = address
            return object()

        monkeypatch.setattr(
            scanner,
            "create_connection",
            fake_create_connection,
        )

        adapter = session.get_adapter("https://example.com")

        pool = adapter.get_connection("https://example.com")

        # Create the HTTPS connection object.
        connection = pool._new_conn()

        # Open its socket using the mocked connection function.
        connection._new_conn()

        assert connected_address["address"] == (
            "93.184.216.34",
            443,
        )

        assert connection.host == "example.com"

        assert connection.pinned_ip == "93.184.216.34"

    finally:
        session.close()


# --------------------------------------------------
# Scanner Rejection Tests
# --------------------------------------------------

def test_scan_website_rejects_unauthorized_target():
    scope = {
        "authorized_domains": [],
        "allow_subdomains": False,
        "request_timeout": 8,
    }

    result = scan_website("https://example.com", scope)

    assert result["scan_status"] == "REJECTED"
    assert result["vulnerability_status"] == "NOT_SCANNED"


def test_scan_website_rejects_invalid_target():
    scope = {
        "authorized_domains": [],
        "allow_subdomains": False,
        "request_timeout": 8,
    }

    result = scan_website("invalid-url", scope)

    assert result["scan_status"] == "REJECTED"
    assert result["vulnerability_status"] == "NOT_SCANNED"


# --------------------------------------------------
# Redirect Inspection Tests
# --------------------------------------------------

def test_inspect_redirect_detects_no_redirect():
    response = SimpleNamespace(
        is_redirect=False,
        headers={},
    )

    result = scanner.inspect_redirect(
        "https://example.com",
        response,
        {},
    )

    assert result["redirect_detected"] is False
    assert result["redirect_scope_status"] == "NOT_A_REDIRECT"


def test_inspect_redirect_blocks_external_domain():
    scope = {
        "authorized_domains": ["example.com"],
        "allow_subdomains": True,
    }

    response = SimpleNamespace(
        is_redirect=True,
        headers={
            "Location": "https://another-domain.com/login",
        },
    )

    result = scanner.inspect_redirect(
        "https://example.com",
        response,
        scope,
    )

    assert result["redirect_detected"] is True
    assert result["redirect_scope_status"] == "BLOCKED_DESTINATION"
    assert "authorized scope" in result["redirect_reason"]


def test_inspect_redirect_allows_authorized_relative_destination(monkeypatch):
    scope = {
        "authorized_domains": ["example.com"],
        "allow_subdomains": True,
    }

    monkeypatch.setattr(
        scanner,
        "is_public_host",
        lambda hostname: True,
    )

    response = SimpleNamespace(
        is_redirect=True,
        headers={"Location": "/login"},
    )

    result = scanner.inspect_redirect(
        "https://example.com/account",
        response,
        scope,
    )

    assert result["redirect_detected"] is True
    assert result["redirect_url"] == "https://example.com/login"
    assert result["redirect_scope_status"] == "AUTHORIZED_DESTINATION"


def test_inspect_redirect_blocks_private_ip_destination():
    scope = {
        "authorized_domains": ["192.168.1.10"],
        "allow_subdomains": False,
    }

    response = SimpleNamespace(
        is_redirect=True,
        headers={
            "Location": "http://192.168.1.10/admin",
        },
    )

    result = scanner.inspect_redirect(
        "https://example.com",
        response,
        scope,
    )

    assert result["redirect_detected"] is True
    assert result["redirect_scope_status"] == "BLOCKED_DESTINATION"


# --------------------------------------------------
# Manual Redirect Following Test Helpers
# --------------------------------------------------

class FakeResponse:
    def __init__(
        self,
        is_redirect=False,
        headers=None,
        status_code=200,
    ):
        self.is_redirect = is_redirect
        self.headers = headers or {}
        self.status_code = status_code
        self.encoding = "utf-8"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, chunk_size=8192):
        return iter([b""])


class FakeCookies:
    def clear(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requested_urls = []
        self.cookies = FakeCookies()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, url, **kwargs):
        self.requested_urls.append(url)

        assert kwargs["allow_redirects"] is False

        return self.responses.pop(0)


def fake_php_not_detected():
    return {
        "php_detected": False,
        "classification": "NOT_DETECTED",
        "confidence": "NONE",
        "php_version": None,
        "version_source": None,
        "strong_indicators": [],
        "weak_indicators": [],
        "evidence": [],
    }


# --------------------------------------------------
# Manual Redirect Following Tests
# --------------------------------------------------

def test_scan_website_follows_authorized_redirect(monkeypatch):
    scope = {
        "authorized_domains": ["example.com"],
        "allow_subdomains": True,
        "request_timeout": 8,
        "max_redirects": 5,
    }

    monkeypatch.setattr(
        scanner,
        "validate_url",
        lambda url, scope: (True, None),
    )

    fake_session = FakeSession([
        FakeResponse(
            is_redirect=True,
            status_code=301,
            headers={"Location": "https://www.example.com"},
        ),
        FakeResponse(
            is_redirect=False,
            status_code=200,
        ),
    ])

    monkeypatch.setattr(
        scanner,
        "create_http_session",
        lambda: fake_session,
    )

    monkeypatch.setattr(
        scanner,
        "identify_php",
        lambda headers, body: fake_php_not_detected(),
    )

    result = scan_website("https://example.com", scope)

    assert result["scan_status"] == "COMPLETED"
    assert result["final_url"] == "https://www.example.com"
    assert result["redirect_detected"] is True
    assert result["redirect_followed"] is True
    assert result["redirect_chain"][0]["followed"] is True

    assert fake_session.requested_urls == [
        "https://example.com",
        "https://www.example.com",
    ]


def test_scan_website_blocks_unauthorized_redirect(monkeypatch):
    scope = {
        "authorized_domains": ["example.com"],
        "allow_subdomains": False,
        "request_timeout": 8,
        "max_redirects": 5,
    }

    def fake_validate_url(url, scope):
        if url == "https://example.com":
            return True, None

        return False, "Domain is not in the authorized scope."

    monkeypatch.setattr(
        scanner,
        "validate_url",
        fake_validate_url,
    )

    fake_session = FakeSession([
        FakeResponse(
            is_redirect=True,
            status_code=302,
            headers={"Location": "https://another-domain.com"},
        ),
    ])

    monkeypatch.setattr(
        scanner,
        "create_http_session",
        lambda: fake_session,
    )

    result = scan_website("https://example.com", scope)

    assert result["scan_status"] == "REDIRECT_BLOCKED"
    assert result["redirect_scope_status"] == "BLOCKED_DESTINATION"
    assert result["redirect_followed"] is False

    # The external destination must never receive a request.
    assert fake_session.requested_urls == [
        "https://example.com",
    ]


def test_blocked_redirect_preserves_safe_response_evidence(monkeypatch):
    scope = {
        "authorized_domains": ["example.com"],
        "allow_subdomains": False,
        "request_timeout": 8,
        "max_redirects": 5,
    }

    def fake_validate_url(url, scope):
        if url == "https://example.com":
            return True, None

        return False, "Domain is not in the authorized scope."

    monkeypatch.setattr(
        scanner,
        "validate_url",
        fake_validate_url,
    )

    fake_session = FakeSession([
        FakeResponse(
            is_redirect=True,
            status_code=302,
            headers={
                "Location": "https://another-domain.com",
                "X-Powered-By": "PHP/8.2.0",
                "Set-Cookie": "PHPSESSID=secret-session-value; Path=/",
            },
        ),
    ])

    monkeypatch.setattr(
        scanner,
        "create_http_session",
        lambda: fake_session,
    )

    result = scan_website("https://example.com", scope)

    assert result["scan_status"] == "REDIRECT_BLOCKED"
    assert result["http_status"] == 302

    assert result["php_detected"] is True
    assert result["php_version"] == "8.2.0"

    assert result["http_headers"]["x-powered-by"] == "PHP/8.2.0"
    assert result["http_headers"]["set-cookie-names"] == ["PHPSESSID"]

    assert "secret-session-value" not in str(result)

    assert result["evidence"]
    assert result["vulnerability_confirmed"] is False

    # The external destination must never receive a request.
    assert fake_session.requested_urls == [
        "https://example.com",
    ]


def test_scan_website_stops_redirect_loop(monkeypatch):
    scope = {
        "authorized_domains": ["example.com"],
        "allow_subdomains": True,
        "request_timeout": 8,
        "max_redirects": 5,
    }

    monkeypatch.setattr(
        scanner,
        "validate_url",
        lambda url, scope: (True, None),
    )

    fake_session = FakeSession([
        FakeResponse(
            is_redirect=True,
            status_code=302,
            headers={"Location": "https://example.com/next"},
        ),
        FakeResponse(
            is_redirect=True,
            status_code=302,
            headers={"Location": "https://example.com"},
        ),
    ])

    monkeypatch.setattr(
        scanner,
        "create_http_session",
        lambda: fake_session,
    )

    result = scan_website("https://example.com", scope)

    assert result["scan_status"] == "REDIRECT_STOPPED"
    assert result["redirect_scope_status"] == "REDIRECT_LOOP"
    assert result["redirect_followed"] is True

    assert len(fake_session.requested_urls) == 2
