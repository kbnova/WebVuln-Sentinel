
"""Tests for independent PHP CVE matching."""

from app.cve_checker import check_cves


def test_detects_both_configured_cves():
    results = check_cves("8.3.20")

    assert len(results) == 2

    cve_ids = {item["cve"] for item in results}

    assert "CVE-2026-109618" in cve_ids
    assert "CVE-2026-109619" in cve_ids


def test_identifies_potential_version_match():
    results = check_cves("8.3.20")

    for result in results:
        assert result["assessment"] == "POTENTIAL_VERSION_MATCH"
        assert result["version_status"] == "POTENTIALLY_AFFECTED"


def test_identifies_version_at_fixed_threshold():
    results = check_cves("8.3.36")

    for result in results:
        assert result["assessment"] == "NO_VERSION_MATCH_DISCLOSED"


def test_unsupported_branch_requires_review():
    results = check_cves("8.1.29")

    for result in results:
        assert result["assessment"] == "INCONCLUSIVE"
        assert result["version_status"] == "REQUIRES_VENDOR_CHECK"
        assert result["support_status"] == "UPSTREAM_EOL"


def test_invalid_version_is_inconclusive():
    results = check_cves("invalid")

    for result in results:
        assert result["assessment"] == "INCONCLUSIVE"
        assert result["version_status"] == "UNKNOWN"


def test_cves_are_assessed_independently():
    rules = {
        "fixed_versions": {},
        "advisories": [
            {
                "cve": "CVE-TEST-001",
                "affected_versions": {
                    "8.3": "8.3.20"
                }
            },
            {
                "cve": "CVE-TEST-002",
                "affected_versions": {
                    "8.3": "8.3.30"
                }
            }
        ]
    }

    results = check_cves("8.3.25", rules)

    assert results[0]["assessment"] == "NO_VERSION_MATCH_DISCLOSED"
    assert results[1]["assessment"] == "POTENTIAL_VERSION_MATCH"
