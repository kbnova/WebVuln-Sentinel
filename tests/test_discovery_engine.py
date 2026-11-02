"""Tests for the authorised discovery engine."""

import pytest

from app.discovery.discovery_engine import DiscoveryEngine


class FakeProvider:

    def search(self, query, limit=10):
        return [
            {
                "website": "https://api.example.com",
                "source": "test"
            },
            {
                "website": "https://www.example.com",
                "source": "test"
            }
        ][:limit]


def test_discovery_accepts_authorized_domain():
    engine = DiscoveryEngine(
        providers=[FakeProvider()],
        scope={"authorized_domains": ["example.com"], "allow_subdomains": True}
    )

    results = engine.discover("example.com")

    assert len(results) == 2


def test_discovery_rejects_unauthorized_domain():
    engine = DiscoveryEngine(
        providers=[FakeProvider()],
        scope={"authorized_domains": ["example.com"], "allow_subdomains": True}
    )

    with pytest.raises(PermissionError):
        engine.discover("other.com")


def test_discovery_rejects_unapproved_subdomain():
    engine = DiscoveryEngine(
        providers=[FakeProvider()],
        scope={
            "authorized_domains": ["example.com"],
            "allow_subdomains": False
        }
    )

    with pytest.raises(PermissionError):
        engine.discover("api.example.com")


def test_discovery_accepts_approved_subdomain():
    engine = DiscoveryEngine(
        providers=[FakeProvider()],
        scope={
            "authorized_domains": ["example.com"],
            "allow_subdomains": True
        }
    )

    results = engine.discover("api.example.com")

    assert len(results) == 2


def test_discovery_rejects_invalid_limit():
    engine = DiscoveryEngine(
        providers=[FakeProvider()],
        scope={"authorized_domains": ["example.com"]}
    )

    with pytest.raises(ValueError):
        engine.discover("example.com", limit=0)
        
def test_discovery_rejects_unapproved_candidate_subdomains():
    engine = DiscoveryEngine(
        providers=[FakeProvider()],
        scope={
            "authorized_domains": ["example.com"],
            "allow_subdomains": False
        }
    )

    results = engine.discover("example.com")

    assert results == []        