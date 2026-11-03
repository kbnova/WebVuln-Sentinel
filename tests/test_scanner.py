
import socket

import pytest

import app.scanner as scanner
from types import SimpleNamespace

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