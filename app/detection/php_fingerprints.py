
"""Evidence-based PHP technology identification.

This module analyses supplied HTTP response data only.
It does not make network requests or confirm vulnerabilities.
"""

import re


PHP_VERSION_PATTERN = re.compile(
    r"\bPHP\s*/?\s*(\d+\.\d+\.\d+)\b",
    re.IGNORECASE
)

PHP_ERROR_PATTERNS = {
    "PHP fatal error": re.compile(
        r"\bFatal error\s*:",
        re.IGNORECASE
    ),
    "PHP warning": re.compile(
        r"\bWarning\s*:.*?\bin\s+.+?\bon\s+line\s+\d+",
        re.IGNORECASE
    ),
    "PHP parse error": re.compile(
        r"\bParse error\s*:",
        re.IGNORECASE
    ),
    "PHP uncaught exception": re.compile(
        r"\bUncaught\s+(?:Error|Exception)\b",
        re.IGNORECASE
    )
}

WEAK_BODY_PATTERNS = {
    "WordPress content directory": re.compile(
        r"wp-content/",
        re.IGNORECASE
    ),
    "WordPress includes directory": re.compile(
        r"wp-includes/",
        re.IGNORECASE
    ),
    "PHP file reference": re.compile(
        r"""(?:href|src|action)\s*=\s*["'][^"']*\.php(?:[?#][^"']*)?["']""",
        re.IGNORECASE
    )
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

    # Check headers for explicit PHP identification.
    for header_name in ("x-powered-by", "server", "x-php-version"):
        value = normalized_headers.get(header_name, "")

        if "php" in value.lower():
            strong_indicators.append(header_name)

            evidence.append({
                "indicator": header_name,
                "source": "HTTP header",
                "value": value[:200],
                "strength": "STRONG"
            })

            match = PHP_VERSION_PATTERN.search(value)

            if match and php_version is None:
                php_version = match.group(1)
                version_source = header_name

    # Check for PHP session cookies.
    cookie_text = " ".join(
        value
        for key, value in normalized_headers.items()
        if key in ("set-cookie", "cookie")
    )

    if re.search(r"\bPHPSESSID\b", cookie_text, re.IGNORECASE):
        strong_indicators.append("PHP session cookie")

        evidence.append({
            "indicator": "PHP session cookie",
            "source": "HTTP cookie",
            "value": "PHPSESSID",
            "strength": "STRONG"
        })

    # Check for characteristic PHP runtime error messages.
    for label, pattern in PHP_ERROR_PATTERNS.items():
        if pattern.search(body):
            strong_indicators.append(label)

            evidence.append({
                "indicator": label,
                "source": "HTTP response body",
                "value": label,
                "strength": "STRONG"
            })

    # Check weaker technology fingerprints.
    for label, pattern in WEAK_BODY_PATTERNS.items():
        if pattern.search(body):
            weak_indicators.append(label)

            evidence.append({
                "indicator": label,
                "source": "HTTP response body",
                "value": label,
                "strength": "WEAK"
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
        "vulnerability_confirmed": False
    }
