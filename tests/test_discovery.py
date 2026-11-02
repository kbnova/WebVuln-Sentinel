"""Tests for passive Certificate Transparency discovery."""

import pytest

from app.discovery.crtsh_provider import CrtShProvider


class FakeResponse:

    def __init__(self, records):
        self.records = records

    def raise_for_status(self):
        pass

    def json(self):
        return self.records


def test_discovers_subdomains(monkeypatch):
    records = [
        {
            "name_value": (
                "api.example.com\n"
                "www.example.com\n"
                "*.example.com"
            )
        }
    ]

    monkeypatch.setattr(
        "app.discovery.crtsh_provider.requests.get",
        lambda *args, **kwargs: FakeResponse(records)
    )

    results = CrtShProvider().search("example.com", limit=10)

    websites = [item["website"] for item in results]

    assert "https://api.example.com" in websites
    assert "https://www.example.com" in websites
    assert len(websites) == 2


def test_rejects_invalid_domain():
    with pytest.raises(ValueError):
        CrtShProvider().search("invalid domain")


def test_rejects_invalid_limit():
    with pytest.raises(ValueError):
        CrtShProvider().search("example.com", limit=0)


def test_respects_result_limit(monkeypatch):
    records = [
        {
            "name_value": (
                "one.example.com\n"
                "two.example.com\n"
                "three.example.com"
            )
        }
    ]

    monkeypatch.setattr(
        "app.discovery.crtsh_provider.requests.get",
        lambda *args, **kwargs: FakeResponse(records)
    )

    results = CrtShProvider().search("example.com", limit=2)

    assert len(results) == 2


def test_does_not_return_unrelated_domains(monkeypatch):
    records = [
        {
            "name_value": (
                "api.example.com\n"
                "attacker-example.com\n"
                "other.com"
            )
        }
    ]

    monkeypatch.setattr(
        "app.discovery.crtsh_provider.requests.get",
        lambda *args, **kwargs: FakeResponse(records)
    )

    results = CrtShProvider().search("example.com")

    assert len(results) == 1
    assert results[0]["website"] == "https://api.example.com"