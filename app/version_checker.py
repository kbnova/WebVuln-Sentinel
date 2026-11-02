
"""Compare an observed PHP version with configured release thresholds."""

import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RULES_FILE = BASE_DIR / "data" / "vulnerability_rules.json"


def load_rules(path=None):
    rules_path = Path(path) if path else RULES_FILE

    with rules_path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def parse_version(version):
    if not isinstance(version, str):
        return None

    match = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", version)

    if not match:
        return None

    return tuple(map(int, match.groups()))


def check_version(version, rules=None):
    if rules is None:
        rules = load_rules()

    current_version = parse_version(version)

    if current_version is None:
        return "UNKNOWN"

    branch = f"{current_version[0]}.{current_version[1]}"

    fixed_version = rules.get("fixed_versions", {}).get(branch)

    if not fixed_version:
        return "REQUIRES_VENDOR_CHECK"

    fixed = parse_version(fixed_version)

    if fixed is None:
        raise ValueError(f"Invalid fixed version: {fixed_version}")

    if current_version < fixed:
        return "POTENTIALLY_AFFECTED"

    return "FIXED_VERSION_DISCLOSED"
