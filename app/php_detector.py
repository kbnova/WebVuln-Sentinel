
"""Detect publicly exposed PHP indicators from HTTP response data."""

import re


PHP_VERSION_PATTERN = re.compile(
    r"\bPHP\s*/?\s*(\d+\.\d+\.\d+)\b",
    re.IGNORECASE
)


def detect_php(headers, body=""):
    """
    Inspect HTTP headers and response content for PHP indicators.

    A detected indicator does not prove that a vulnerability exists.
    """

    indicators = []
    weak_indicators = []
    version = None
    version_source = None

    # Normalize header names so matching is case-insensitive.
    normalized_headers = {
        str(key).lower(): str(value)
        for key, value in (headers or {}).items()
    }

    # Check headers that may disclose PHP information.
    for header_name in ("x-powered-by", "server"):
        value = normalized_headers.get(header_name, "")

        if "php" in value.lower():
            indicators.append(header_name)

            match = PHP_VERSION_PATTERN.search(value)

            if match and version is None:
                version = match.group(1)
                version_source = header_name

    # Check cookies for a PHP session identifier.
    cookie_text = " ".join(
        value
        for key, value in normalized_headers.items()
        if key in ("set-cookie", "cookie")
    )

    if re.search(r"\bPHPSESSID\b", cookie_text, re.IGNORECASE):
        indicators.append("PHP session cookie")

    # WordPress assets are a weak clue, not proof of PHP.
    body_text = body.lower()

    if "wp-content/" in body_text or "wp-includes/" in body_text:
        weak_indicators.append("WordPress asset")

    return {
        "php_detected": bool(indicators),
        "version": version,
        "version_source": version_source,
        "indicators": indicators,
        "weak_indicators": weak_indicators
    }
