
"""Generate structured JSON security assessment reports."""

import json
from datetime import datetime, timezone
from pathlib import Path


def build_report(results):

    risk_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "REVIEW": 0,
        "UNKNOWN": 0
    }

    for result in results:
        risk = result.get("risk", {}).get("risk_level", "UNKNOWN")

        if risk not in risk_counts:
            risk = "UNKNOWN"

        risk_counts[risk] += 1

    report = {
        "project": "WebVuln Sentinel",
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "summary": {
            "total_targets": len(results),
            "risk_counts": risk_counts
        },

        "results": results,

        "limitations": [
            "Only authorized websites should be scanned.",
            "Public version information does not prove vulnerability.",
            "Security fixes may be backported by hosting providers.",
            "This tool does not perform exploit verification."
        ]
    }

    return report


def save_report(results, output_path="reports/results.json"):

    report = build_report(results)

    output_file = Path(output_path)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_file
