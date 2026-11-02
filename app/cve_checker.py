

"""Match PHP version observations against configured CVE records."""

from app.version_checker import check_version, load_rules


def check_cves(version, rules=None):

    if rules is None:
        rules = load_rules()

    version_status = check_version(version, rules)

    advisories = rules.get("advisories", [])

    # Support the original CVE list format too.
    if not advisories:
        advisories = [
            {"cve": cve}
            for cve in rules.get("cves", [])
        ]

    results = []

    for advisory in advisories:

        if version_status == "POTENTIALLY_AFFECTED":
            assessment = "POTENTIAL_VERSION_MATCH"

        elif version_status == "FIXED_VERSION_DISCLOSED":
            assessment = "NO_VERSION_MATCH_DISCLOSED"

        else:
            assessment = "INCONCLUSIVE"

        results.append({
            "cve": advisory.get("cve", "UNKNOWN"),
            "title": advisory.get("title", "PHP security advisory"),
            "severity": advisory.get("severity", "UNKNOWN"),
            "assessment": assessment,
            "version_status": version_status,
            "source": advisory.get("source")
        })

    return results
