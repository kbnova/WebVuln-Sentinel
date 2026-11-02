
"""Analyze scan findings and assign a conservative risk level."""


def analyze_risk(version_status, cve_matches=None):

    cve_matches = cve_matches or []

    if version_status == "POTENTIALLY_AFFECTED":

        return {
            "risk_level": "HIGH",
            "priority": "P1 - Urgent review",
            "confidence": "LOW",
            "reason": (
                "The detected PHP version is below the configured "
                "security release threshold. Manual verification is required."
            ),
            "confirmed_vulnerability": False,
            "matched_cves": len(cve_matches)
        }

    elif version_status == "FIXED_VERSION_DISCLOSED":

        return {
            "risk_level": "LOW",
            "priority": "P3 - Routine review",
            "confidence": "LOW",
            "reason": (
                "The disclosed PHP version is at or above the "
                "configured security release threshold."
            ),
            "confirmed_vulnerability": False,
            "matched_cves": 0
        }

    elif version_status == "REQUIRES_VENDOR_CHECK":

        return {
            "risk_level": "REVIEW",
            "priority": "P2 - Manual review",
            "confidence": "LOW",
            "reason": (
                "This PHP branch has no configured fixed-version "
                "threshold. Check the hosting provider's security advisories."
            ),
            "confirmed_vulnerability": False,
            "matched_cves": len(cve_matches)
        }

    else:

        return {
            "risk_level": "UNKNOWN",
            "priority": "P3 - Gather more evidence",
            "confidence": "NONE",
            "reason": (
                "Insufficient public information to assess the PHP version."
            ),
            "confirmed_vulnerability": False,
            "matched_cves": 0
        }
