
"""Main entry point for WebVuln Sentinel."""

import json
from pathlib import Path

from app.scanner import scan_website, load_scope
from app.report_generator import save_report


BASE_DIR = Path(__file__).resolve().parent.parent
TARGETS_FILE = BASE_DIR / "data" / "targets.txt"
REPORT_FILE = BASE_DIR / "reports" / "results.json"


def load_targets():
    """Read target URLs from the targets file."""
    with TARGETS_FILE.open("r", encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        ]


def main():
    print("=" * 55)
    print("             WEBVULN SENTINEL")
    print("       Authorized PHP Security Scanner")
    print("=" * 55)

    try:
        scope = load_scope()
        targets = load_targets()

    except (FileNotFoundError, json.JSONDecodeError) as error:
        print(f"\nConfiguration error: {error}")
        return

    max_targets = scope.get("max_targets", 10)

    if not isinstance(max_targets, int) or max_targets < 1:
        print("\nInvalid max_targets setting in config/scope.json.")
        return

    if not targets:
        print("\nNo targets found in data/targets.txt.")
        return

    if len(targets) > max_targets:
        print(
            f"\nTarget limit is {max_targets}. "
            f"Only the first {max_targets} targets will be processed."
        )
        targets = targets[:max_targets]

    print(f"\nTargets loaded: {len(targets)}")
    print("Starting authorized security assessment...\n")

    results = []

    for number, website in enumerate(targets, start=1):
        print(f"[{number}/{len(targets)}] Checking {website}")

        result = scan_website(website, scope)
        results.append(result)

        print(json.dumps(result, indent=4))
        print("-" * 55)

    try:
        saved_path = save_report(results, REPORT_FILE)
        print("\nAssessment completed.")
        print(f"Report saved to: {saved_path}")

    except OSError as error:
        print(f"\nCould not save report: {error}")


if __name__ == "__main__":
    main()
