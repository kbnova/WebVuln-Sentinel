import re

def detect_php(headers, body):

    indicators = []
    version = None

    for key in ["X-Powered-By", "Server"]:

        value = headers.get(key, "")

        if "php" in value.lower():

            indicators.append(key)

            match = re.search(
                r"PHP/?\s*(\d+\.\d+\.\d+)",
                value,
                re.IGNORECASE
            )

            if match:
                version = match.group(1)

    if "wp-content/" in body.lower():
        indicators.append("WordPress asset")

    if "PHPSESSID" in str(headers).upper():
        indicators.append("PHP session cookie")

    return {
        "php_detected": bool(indicators),
        "version": version,
        "indicators": indicators
    }
from app.php_detector import detect_php


def test_php_version_detection():

    headers = {
        "X-Powered-By": "PHP/8.3.35"
    }

    result = detect_php(headers, "")

    assert result["php_detected"] is True
    assert result["version"] == "8.3.35"


def test_php_without_version():

    headers = {
        "Set-Cookie": "PHPSESSID=12345"
    }

    result = detect_php(headers, "")

    assert result["php_detected"] is True
    assert result["version"] is None


def test_wordpress_detection():

    body = '<link href="/wp-content/themes/test.css">'

    result = detect_php({}, body)

    assert result["php_detected"] is False
    assert result["version"] is None
    assert result["weak_indicators"] == ["WordPress asset"]



def test_no_php_indicators():

    result = detect_php(
        {"Server": "nginx"},
        "<html>Hello World</html>"
    )

    assert result["php_detected"] is False