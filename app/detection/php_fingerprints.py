
"""Evidence-based PHP technology identification.

This module analyses supplied HTTP response data only.
It does not make network requests or confirm vulnerabilities.
"""

import re


PHP_VERSION_PATTERN = re.compile(
    r"\bPHP\s*/?\s*(\d+\.\d+\.\d+)\b",
    re.IGNORECASE,
)

# A PHP runtime error is useful evidence only when it is
# accompanied by a PHP file reference.
PHP_RUNTIME_ERROR_PATTERN = re.compile(
    r"\b(?:Fatal error|Parse error|Warning|Uncaught\s+(?:Error|Exception))\b"
    r".{0,500}?\b[^\s\"'<>]*\.php(?:\b|[?#])",
    re.IGNORECASE | re.DOTALL,
)

PHP_FILE_REFERENCE_PATTERN = re.compile(
    r"""(?:href|src|action)\s*=\s*["'][^"']*\.php(?:[?#][^"']*)?["']""",
    re.IGNORECASE,
)

WEAK_BODY_PATTERNS = {
    "WordPress content directory": re.compile(
        r"wp-content/",
        re.IGNORECASE,
    ),
    "WordPress includes directory": re.compile(
        r"wp-includes/",
        re.IGNORECASE,
    ),
    "PHP file reference": PHP_FILE_REFERENCE_PATTERN,
}


def identify_php(headers=None, body=""):
    """Identify PHP-related indicators from supplied response data."""

    headers = headers or {}
    body = body or ""

    if not isinstance(headers, dict):
        raise ValueError("Headers must be a dictionary.")

    if not isinstance(body, str):
        raise ValueError("Response body must be a string.")

    normalized_headers = {
        str(key).lower(): str(value)
        for key, value in headers.items()
    }

    strong_indicators = []
    weak_indicators = []
    evidence = []

    php_version = None
    version_source = None

    # Check HTTP headers for explicit PHP identification.
    for header_name in ("x-powered-by", "server", "x-php-version"):
        value = normalized_headers.get(header_name, "")

        if "php" in value.lower():
            strong_indicators.append(header_name)

            evidence.append({
                "indicator": header_name,
                "source": "HTTP header",
                "value": value[:200],
                "strength": "STRONG",
            })

            match = PHP_VERSION_PATTERN.search(value)

            if match and php_version is None:
                php_version = match.group(1)
                version_source = header_name

    # Check cookie names only. Never include cookie values,
    # because they may contain session tokens.
    cookie_names = []

    for header_name in ("set-cookie", "cookie"):
        cookie_text = normalized_headers.get(header_name, "")

        for part in cookie_text.split(";"):
            cookie_name = part.strip().split("=", 1)[0].strip()

            if cookie_name:
                cookie_names.append(cookie_name)

    if any(
        name.lower() == "phpsessid"
        for name in cookie_names
    ):
        strong_indicators.append("PHP session cookie")

        evidence.append({
            "indicator": "PHP session cookie",
            "source": "HTTP cookie",
            "value": "PHPSESSID",
            "strength": "STRONG",
        })

    # A runtime error counts only when a PHP file reference
    # appears in the same error context.
    if PHP_RUNTIME_ERROR_PATTERN.search(body):
        indicator = "PHP runtime error with .php file reference"

        strong_indicators.append(indicator)

        evidence.append({
            "indicator": indicator,
            "source": "HTTP response body",
            "value": "PHP runtime error and .php file reference",
            "strength": "STRONG",
        })

    # Check weaker technology fingerprints.
    for label, pattern in WEAK_BODY_PATTERNS.items():
        if pattern.search(body):
            weak_indicators.append(label)

            evidence.append({
                "indicator": label,
                "source": "HTTP response body",
                "value": label,
                "strength": "WEAK",
            })

    if strong_indicators:
        classification = "PHP_INDICATED"
        confidence = "HIGH"
    elif weak_indicators:
        classification = "POSSIBLE_PHP"
        confidence = "LOW"
    else:
        classification = "NOT_DETECTED"
        confidence = "NONE"

    return {
        "classification": classification,
        "confidence": confidence,
        "php_detected": bool(strong_indicators),
        "php_version": php_version,
        "version_source": version_source,
        "strong_indicators": strong_indicators,
        "weak_indicators": weak_indicators,
        "evidence": evidence,
        "vulnerability_confirmed": False,
    }
