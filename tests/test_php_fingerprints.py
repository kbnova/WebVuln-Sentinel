
from app.detection.php_fingerprints import identify_php


def test_identifies_explicit_php_version():
    result = identify_php({
        "X-Powered-By": "PHP/8.2.10"
    })

    assert result["classification"] == "PHP_INDICATED"
    assert result["php_version"] == "8.2.10"
    assert result["confidence"] == "HIGH"


def test_identifies_php_without_version():
    result = identify_php({
        "X-Powered-By": "PHP"
    })

    assert result["classification"] == "PHP_INDICATED"
    assert result["php_version"] is None


def test_identifies_php_session_cookie():
    result = identify_php({
        "Set-Cookie": "PHPSESSID=abc123; Path=/"
    })

    assert result["classification"] == "PHP_INDICATED"
    assert "PHP session cookie" in result["strong_indicators"]


def test_cookie_evidence_does_not_expose_session_value():
    result = identify_php({
        "Set-Cookie": "PHPSESSID=secret-session-token; Path=/"
    })

    cookie_evidence = [
        item for item in result["evidence"]
        if item["source"] == "HTTP cookie"
    ]

    assert cookie_evidence
    assert "secret-session-token" not in str(cookie_evidence)


def test_identifies_php_runtime_error_with_php_file_reference():
    result = identify_php(
        headers={},
        body="Fatal error: Uncaught Error in /var/www/index.php on line 10"
    )

    assert result["classification"] == "PHP_INDICATED"
    assert (
        "PHP runtime error with .php file reference"
        in result["strong_indicators"]
    )


def test_generic_fatal_error_is_not_php_evidence():
    result = identify_php(
        headers={},
        body="Fatal error: Something went wrong."
    )

    assert result["classification"] == "NOT_DETECTED"
    assert result["php_detected"] is False


def test_generic_parse_error_is_not_php_evidence():
    result = identify_php(
        headers={},
        body="Parse error: Unexpected input."
    )

    assert result["classification"] == "NOT_DETECTED"
    assert result["php_detected"] is False


def test_identifies_possible_wordpress():
    result = identify_php(
        headers={},
        body='<script src="/wp-content/themes/site.js"></script>'
    )

    assert result["classification"] == "POSSIBLE_PHP"
    assert result["confidence"] == "LOW"


def test_identifies_php_file_reference_as_weak_evidence():
    result = identify_php(
        headers={},
        body='<a href="/contact.php">Contact</a>'
    )

    assert result["classification"] == "POSSIBLE_PHP"


def test_does_not_detect_php_without_evidence():
    result = identify_php(
        headers={"Server": "nginx"},
        body="<html><h1>Hello</h1></html>"
    )

    assert result["classification"] == "NOT_DETECTED"


def test_never_confirms_vulnerability():
    result = identify_php({
        "X-Powered-By": "PHP/8.2.10"
    })

    assert result["vulnerability_confirmed"] is False


def test_returns_evidence_for_php_detection():
    result = identify_php({
        "X-Powered-By": "PHP/8.2.10"
    })

    assert len(result["evidence"]) > 0
    assert result["evidence"][0]["strength"] == "STRONG"
