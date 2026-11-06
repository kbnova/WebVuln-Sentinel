
"""Match PHP versions against individual configured CVE records."""

from app.version_checker import load_rules, parse_version


def check_cves(version, rules=None):
    """Assess each configured CVE independently against the observed PHP version."""

    if rules is None:
        rules = load_rules()

    current_version = parse_version(version)

    advisories = rules.get("advisories", [])

    # Support the original CVE list format for older configurations.
    if not advisories:
        advisories = [
            {"cve": cve}
            for cve in rules.get("cves", [])
        ]

    branch = (
        f"{current_version[0]}.{current_version[1]}"
        if current_version is not None
        else None
    )

    eol_branches = rules.get("end_of_life_branches", [])
    vendor_required_branches = rules.get(
        "vendor_verification_required", []
    )

    results = []

    for advisory in advisories:
        affected_versions = advisory.get("affected_versions", {})

        # Each CVE uses its own configured fixed-version thresholds.
        fixed_version = (
            affected_versions.get(branch)
            if branch is not None
            else None
        )

        if current_version is None:
            version_status = "UNKNOWN"

        elif fixed_version is None:
            version_status = "REQUIRES_VENDOR_CHECK"

        else:
            fixed = parse_version(fixed_version)

            if fixed is None:
                raise ValueError(
                    f"Invalid fixed version for "
                    f"{advisory.get('cve', 'UNKNOWN')}: {fixed_version}"
                )

            if current_version < fixed:
                version_status = "POTENTIALLY_AFFECTED"
            else:
                version_status = "FIXED_VERSION_DISCLOSED"

        if version_status == "POTENTIALLY_AFFECTED":
            assessment = "POTENTIAL_VERSION_MATCH"

        elif version_status == "FIXED_VERSION_DISCLOSED":
            assessment = "NO_VERSION_MATCH_DISCLOSED"

        else:
            assessment = "INCONCLUSIVE"

        support_status = (
            "UPSTREAM_EOL"
            if branch in eol_branches
            else "NOT_MARKED_EOL"
        )

        vendor_verification = (
            branch in vendor_required_branches
            if branch is not None
            else None
        )

        results.append({
            "cve": advisory.get("cve", "UNKNOWN"),
            "title": advisory.get(
                "title",
                "PHP security advisory"
            ),
            "severity": advisory.get("severity", "UNKNOWN"),
            "assessment": assessment,
            "version_status": version_status,
            "fixed_version": fixed_version,
            "support_status": support_status,
            "vendor_verification_required": vendor_verification,
            "source": advisory.get("source")
        })

    return results
