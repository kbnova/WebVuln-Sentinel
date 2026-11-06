
"""Generate structured JSON security assessment reports."""

import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_DIR = BASE_DIR / "reports"


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

    return {
        "project": "WebVuln Sentinel",
        "report_version": "1.1",
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


def save_report(results, output_path=None):
    """Save a report without ever overwriting an existing report."""

    report = build_report(results)

    if output_path is None:
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d_%H%M%S_%f"
        )
        output_file = DEFAULT_REPORT_DIR / f"scan_{timestamp}.json"

    else:
        output_file = Path(output_path)

        if not output_file.is_absolute():
            output_file = BASE_DIR / output_file

    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation prevents accidental overwriting.
    # If a filename already exists, generate another filename.
    candidate = output_file
    counter = 1

    while True:
        try:
            with candidate.open("x", encoding="utf-8") as file:
                json.dump(report, file, indent=4)

            return candidate

        except FileExistsError:
            candidate = output_file.with_name(
                f"{output_file.stem}_{counter}{output_file.suffix}"
            )
            counter += 1
