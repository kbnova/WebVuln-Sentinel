
"""Safe, scope-restricted PHP security assessment scanner."""

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util.connection import create_connection

from app.detection.php_fingerprints import identify_php
from app.version_checker import check_version
from app.cve_checker import check_cves
from app.risk_analyzer import analyze_risk


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
SCOPE_FILE = BASE_DIR / "config" / "scope.json"

USER_AGENT = "WebVuln-Sentinel/1.0"
MAX_RESPONSE_BYTES = 64 * 1024


# --------------------------------------------------
# DNS-Pinned HTTP Connection Classes
# --------------------------------------------------

class PinnedHTTPConnection(HTTPConnection):
    """HTTP connection that connects to a prevalidated IP."""

    def __init__(self, *args, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        try:
            return create_connection(
                (self.pinned_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )

        except socket.timeout as error:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.pinned_ip} timed out.",
            ) from error

        except OSError as error:
            raise NewConnectionError(
                self,
                f"Failed to connect to pinned IP {self.pinned_ip}: {error}",
            ) from error


class PinnedHTTPSConnection(HTTPSConnection):
    """HTTPS connection with IP pinning and hostname TLS verification."""

    def __init__(self, *args, pinned_ip, **kwargs):
        self.pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        try:
            return create_connection(
                (self.pinned_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )

        except socket.timeout as error:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.pinned_ip} timed out.",
            ) from error

        except OSError as error:
            raise NewConnectionError(
                self,
                f"Failed to connect to pinned IP {self.pinned_ip}: {error}",
            ) from error


class PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = PinnedHTTPConnection


class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = PinnedHTTPSConnection


# --------------------------------------------------
# DNS-Pinned Requests Adapter
# --------------------------------------------------

class PinnedIPAdapter(HTTPAdapter):
    """Requests adapter that validates and pins destination IPs."""

    def get_connection(self, url, proxies=None):
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            raise requests.exceptions.ConnectionError(
                "URL hostname is missing."
            )

        if parsed.scheme not in ("http", "https"):
            raise requests.exceptions.ConnectionError(
                "Only HTTP and HTTPS are supported."
            )

        try:
            port = parsed.port or (
                443 if parsed.scheme == "https" else 80
            )

            dns_results = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )

            if not dns_results:
                raise requests.exceptions.ConnectionError(
                    "Hostname did not resolve to any IP address."
                )

            resolved_ips = list(
                dict.fromkeys(
                    result[4][0]
                    for result in dns_results
                )
            )

            # Reject the hostname if any resolved address
            # is not globally routable.
            for address in resolved_ips:
                ip = ipaddress.ip_address(address)

                if not ip.is_global:
                    raise requests.exceptions.ConnectionError(
                        f"Non-public IP address rejected: {address}"
                    )

            # Pin the connection to the first validated IP.
            pinned_ip = resolved_ips[0]

        except requests.exceptions.ConnectionError:
            raise

        except (socket.gaierror, ValueError, OSError) as error:
            raise requests.exceptions.ConnectionError(
                f"DNS resolution or IP validation failed: {error}"
            ) from error

        if parsed.scheme == "https":
            return PinnedHTTPSConnectionPool(
                host=hostname,
                port=port,
                maxsize=1,
                block=True,
                pinned_ip=pinned_ip,
            )

        return PinnedHTTPConnectionPool(
            host=hostname,
            port=port,
            maxsize=1,
            block=True,
            pinned_ip=pinned_ip,
        )


# --------------------------------------------------
# Scope Management
# --------------------------------------------------

def load_scope():
    """Load the authorized scanning scope."""

    with SCOPE_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def is_authorized_domain(hostname, scope):
    """Check whether a hostname is explicitly authorized."""

    allowed_domains = scope.get("authorized_domains", [])
    allow_subdomains = scope.get("allow_subdomains", False)

    hostname = hostname.lower().rstrip(".")

    for domain in allowed_domains:
        domain = domain.lower().strip().rstrip(".")

        if hostname == domain:
            return True

        if allow_subdomains and hostname.endswith("." + domain):
            return True

    return False


# --------------------------------------------------
# Public IP Validation
# --------------------------------------------------

def is_public_host(hostname):
    """Reject hostnames that resolve to non-public IP addresses."""

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False

        return True

    except (socket.gaierror, ValueError, OSError):
        return False


# --------------------------------------------------
# URL Validation
# --------------------------------------------------

def validate_url(url, scope):
    """Validate URL format, authorization, and public destination."""

    if not isinstance(url, str):
        return False, "URL must be a string."

    try:
        parsed = urlparse(url.strip())

        if parsed.scheme.lower() not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "URL does not contain a valid hostname."

        if parsed.username or parsed.password:
            return False, "URLs containing credentials are not allowed."

        # Validate the port.
        _ = parsed.port

        hostname = (
            parsed.hostname.encode("idna")
            .decode("ascii")
            .lower()
        )

        if not is_authorized_domain(hostname, scope):
            return False, "Domain is not in the authorized scope."

        if not is_public_host(hostname):
            return False, (
                "Host does not resolve exclusively to public IP addresses."
            )

        return True, None

    except (ValueError, UnicodeError):
        return False, "Invalid URL."


# --------------------------------------------------
# Redirect Inspection
# --------------------------------------------------

def inspect_redirect(original_url, response, scope):
    """
    Inspect a redirect destination without following it.

    The destination must pass the same authorization and
    public-IP validation as an initial scanning target.
    """

    if not response.is_redirect:
        return {
            "redirect_detected": False,
            "redirect_url": None,
            "redirect_scope_status": "NOT_A_REDIRECT",
            "redirect_reason": None,
        }

    location = response.headers.get("Location")

    if not location:
        return {
            "redirect_detected": True,
            "redirect_url": None,
            "redirect_scope_status": "NO_LOCATION",
            "redirect_reason": "Redirect response has no Location header.",
        }

    try:
        destination = urljoin(original_url, location)

        authorized, reason = validate_url(destination, scope)

        if not authorized:
            return {
                "redirect_detected": True,
                "redirect_url": destination,
                "redirect_scope_status": "BLOCKED_DESTINATION",
                "redirect_reason": reason,
            }

        return {
            "redirect_detected": True,
            "redirect_url": destination,
            "redirect_scope_status": "AUTHORIZED_DESTINATION",
            "redirect_reason": None,
        }

    except (ValueError, UnicodeError) as error:
        return {
            "redirect_detected": True,
            "redirect_url": None,
            "redirect_scope_status": "BLOCKED_DESTINATION",
            "redirect_reason": f"Invalid redirect destination: {error}",
        }


# --------------------------------------------------
# Limited HTTP Response Reader
# --------------------------------------------------

def read_limited_response(response):
    """Read at most MAX_RESPONSE_BYTES from an HTTP response."""

    chunks = []
    total = 0

    for chunk in response.iter_content(chunk_size=8192):

        if not chunk:
            continue

        remaining = MAX_RESPONSE_BYTES - total

        if remaining <= 0:
            break

        chunk = chunk[:remaining]

        chunks.append(chunk)
        total += len(chunk)

        if total >= MAX_RESPONSE_BYTES:
            break

    encoding = response.encoding or "utf-8"

    return b"".join(chunks).decode(
        encoding,
        errors="replace",
    )


# --------------------------------------------------
# HTTP Session Creation
# --------------------------------------------------

def create_http_session():
    """Create a session with proxy and DNS rebinding protections."""

    session = requests.Session()

    # Ignore environment-configured proxies.
    session.trust_env = False

    pinned_adapter = PinnedIPAdapter()

    session.mount("http://", pinned_adapter)
    session.mount("https://", pinned_adapter)

    return session


# --------------------------------------------------
# Main Website Scanner
# --------------------------------------------------

def scan_website(url, scope=None):
    """
    Perform one low-impact HTTP GET request against
    an explicitly authorized website.

    Redirects are inspected but never followed.
    This function does not exploit vulnerabilities.
    """

    if scope is None:
        scope = load_scope()

    # Step 1: Validate authorization and destination.
    authorized, reason = validate_url(url, scope)

    if not authorized:
        return {
            "website": url,
            "scan_status": "REJECTED",
            "vulnerability_status": "NOT_SCANNED",
            "reason": reason,
        }

    try:

        # Step 2: Create protected HTTP session.
        with create_http_session() as session:

            # Step 3: Send one HTTP GET request.
            with session.get(
                url,
                timeout=scope.get("request_timeout", 8),
                headers={
                    "User-Agent": USER_AGENT,
                },
                allow_redirects=False,
                stream=True,
            ) as response:

                # Step 4: Collect response evidence.
                headers = dict(response.headers)

                redirect_info = inspect_redirect(
                    url,
                    response,
                    scope,
                )

                body = read_limited_response(response)

                # Step 5: Detect PHP indicators.
                detection = identify_php(headers, body)

                # Step 6: Analyze PHP evidence.
                if detection["classification"] == "NOT_DETECTED":

                    version_status = "PHP_NOT_DETECTED"
                    cve_matches = []

                    risk = {
                        "risk_level": "UNKNOWN",
                        "priority": "P3 - Gather more evidence",
                        "confidence": "NONE",
                        "reason": (
                            "No public PHP indicators were detected. "
                            "This does not prove that the website "
                            "does not use PHP."
                        ),
                        "confirmed_vulnerability": False,
                        "matched_cves": 0,
                    }

                elif detection["classification"] == "POSSIBLE_PHP":

                    version_status = "POSSIBLE_PHP_REQUIRES_REVIEW"
                    cve_matches = []

                    risk = {
                        "risk_level": "REVIEW",
                        "priority": "P3 - Gather more evidence",
                        "confidence": "LOW",
                        "reason": (
                            "Only weak PHP-related technology indicators "
                            "were found. PHP usage and vulnerability "
                            "status are unverified."
                        ),
                        "confirmed_vulnerability": False,
                        "matched_cves": 0,
                    }

                else:

                    # Step 7: Check the detected PHP version.
                    php_version = detection["php_version"]

                    version_status = check_version(php_version)

                    # Step 8: Match known CVE rules.
                    cve_matches = check_cves(php_version)

                    # Step 9: Analyze risk.
                    risk = analyze_risk(
                        version_status,
                        cve_matches,
                    )

                # Step 10: Return structured results.
                return {
                    "website": url,
                    "scan_status": "COMPLETED",
                    "http_status": response.status_code,

                    "redirect_detected": redirect_info["redirect_detected"],
                    "redirect_url": redirect_info["redirect_url"],
                    "redirect_scope_status": redirect_info[
                        "redirect_scope_status"
                    ],
                    "redirect_reason": redirect_info["redirect_reason"],

                    "php_detected": detection["php_detected"],
                    "php_classification": detection["classification"],
                    "php_confidence": detection["confidence"],
                    "php_version": detection["php_version"],
                    "version_source": detection["version_source"],

                    "indicators": detection["strong_indicators"],
                    "strong_indicators": detection["strong_indicators"],
                    "weak_indicators": detection["weak_indicators"],
                    "evidence": detection["evidence"],

                    "vulnerability_status": version_status,
                    "cve_matches": cve_matches,
                    "risk": risk,

                    # Detection does not prove exploitability.
                    "vulnerability_confirmed": False,
                }

    except requests.RequestException as error:

        return {
            "website": url,
            "scan_status": "ERROR",
            "vulnerability_status": "SCAN_ERROR",
            "error": str(error),
        }
