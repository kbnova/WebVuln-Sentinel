
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
    """Inspect a redirect without following an unauthorized destination."""

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
# Safe HTTP Header Evidence
# --------------------------------------------------

def extract_safe_http_headers(headers, set_cookie_headers=None):
    """Extract relevant HTTP headers without exposing cookie values."""

    normalized_headers = {
        str(key).lower(): str(value)
        for key, value in (headers or {}).items()
    }

    safe_headers = {}

    for header_name in (
        "x-powered-by",
        "x-php-version",
        "server",
    ):
        value = normalized_headers.get(header_name)

        if value:
            safe_headers[header_name] = value[:200]

    cookie_headers = set_cookie_headers or []

    # Fallback for test responses or response objects
    # that do not expose individual raw Set-Cookie headers.
    if not cookie_headers:
        cookie_header = normalized_headers.get("set-cookie", "")

        if cookie_header:
            cookie_headers = [cookie_header]

    cookie_names = []

    for cookie in cookie_headers:
        cookie_name = str(cookie).split(";", 1)[0]
        cookie_name = cookie_name.split("=", 1)[0].strip()

        if cookie_name:
            cookie_names.append(cookie_name)

    if cookie_names:
        safe_headers["set-cookie-names"] = sorted(set(cookie_names))

    return safe_headers


def collect_response_evidence(response, body=""):
    """
    Collect safe HTTP and PHP evidence from a response.

    Redirect responses are inspected using their headers only.
    The scanner does not need to read a redirect response body.
    Cookie values are never included in the returned evidence.
    """

    headers = dict(response.headers or {})

    raw_response = getattr(response, "raw", None)
    raw_headers = getattr(raw_response, "headers", None)
    get_cookie_headers = getattr(raw_headers, "getlist", None)

    if callable(get_cookie_headers):
        set_cookie_headers = get_cookie_headers("Set-Cookie")
    else:
        set_cookie_headers = []

    safe_http_headers = extract_safe_http_headers(
        headers,
        set_cookie_headers,
    )

    detection = identify_php(headers, body)

    return {
        "http_status": getattr(response, "status_code", None),
        "http_headers": safe_http_headers,
        "php_detected": detection["php_detected"],
        "php_classification": detection["classification"],
        "php_confidence": detection["confidence"],
        "php_version": detection["php_version"],
        "version_source": detection["version_source"],
        "indicators": detection["strong_indicators"],
        "strong_indicators": detection["strong_indicators"],
        "weak_indicators": detection["weak_indicators"],
        "evidence": detection["evidence"],
        "vulnerability_confirmed": False,
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
    Perform a low-impact HTTP GET assessment against an
    explicitly authorized website.

    Redirects are followed manually, one hop at a time.
    Every destination must pass authorization and public-IP checks.
    """

    if scope is None:
        scope = load_scope()

    # Step 1: Validate the original target.
    authorized, reason = validate_url(url, scope)

    if not authorized:
        return {
            "website": url,
            "scan_status": "REJECTED",
            "vulnerability_status": "NOT_SCANNED",
            "reason": reason,
            "redirect_detected": False,
            "redirect_followed": False,
            "redirect_chain": [],
            "vulnerability_confirmed": False,
        }

    # Step 2: Set a safe redirect limit.
    max_redirects = scope.get("max_redirects", 5)

    if (
        not isinstance(max_redirects, int)
        or isinstance(max_redirects, bool)
        or max_redirects < 0
        or max_redirects > 10
    ):
        max_redirects = 5

    current_url = url
    visited_urls = {current_url}

    redirect_detected = False
    redirect_followed = False
    redirect_url = None
    redirect_scope_status = "NOT_A_REDIRECT"
    redirect_reason = None
    redirect_chain = []
    redirects_followed = 0

    try:
        # Step 3: Create the protected HTTP session.
        with create_http_session() as session:

            while True:

                # Do not carry cookies from one redirect destination
                # to another.
                session.cookies.clear()

                # Step 4: Request the current authorized URL.
                with session.get(
                    current_url,
                    timeout=scope.get("request_timeout", 8),
                    headers={
                        "User-Agent": USER_AGENT,
                    },
                    allow_redirects=False,
                    stream=True,
                ) as response:

                    # Step 5: Inspect redirects manually.
                    if response.is_redirect:

                        redirect_detected = True

                        redirect_info = inspect_redirect(
                            current_url,
                            response,
                            scope,
                        )

                        destination = redirect_info["redirect_url"]

                        redirect_url = destination
                        redirect_scope_status = redirect_info[
                            "redirect_scope_status"
                        ]
                        redirect_reason = redirect_info[
                            "redirect_reason"
                        ]

                        redirect_chain.append({
                            "from": current_url,
                            "to": destination,
                            "scope_status": redirect_scope_status,
                            "followed": False,
                        })

                        # Capture evidence from this redirect response.
                        # This is useful even when its destination is blocked.
                        response_evidence = collect_response_evidence(
                            response
                        )

                        # Step 6: Stop if the destination is not authorized.
                        if (
                            redirect_scope_status
                            != "AUTHORIZED_DESTINATION"
                        ):
                            return {
                                "website": url,
                                "final_url": current_url,
                                "scan_status": "REDIRECT_BLOCKED",
                                "vulnerability_status": "NOT_SCANNED",
                                "reason": redirect_reason,
                                "redirect_detected": True,
                                "redirect_url": destination,
                                "redirect_scope_status": (
                                    redirect_scope_status
                                ),
                                "redirect_reason": redirect_reason,
                                "redirect_followed": redirect_followed,
                                "redirect_chain": redirect_chain,
                                **response_evidence,
                            }

                        # Step 7: Detect redirect loops.
                        if destination in visited_urls:
                            redirect_scope_status = "REDIRECT_LOOP"
                            redirect_reason = (
                                "Redirect loop detected. "
                                "The repeated destination was not followed."
                            )

                            redirect_chain[-1]["scope_status"] = (
                                redirect_scope_status
                            )

                            return {
                                "website": url,
                                "final_url": current_url,
                                "scan_status": "REDIRECT_STOPPED",
                                "vulnerability_status": "NOT_SCANNED",
                                "reason": redirect_reason,
                                "redirect_detected": True,
                                "redirect_url": destination,
                                "redirect_scope_status": (
                                    redirect_scope_status
                                ),
                                "redirect_reason": redirect_reason,
                                "redirect_followed": redirect_followed,
                                "redirect_chain": redirect_chain,
                                **response_evidence,
                            }

                        # Step 8: Enforce the redirect limit.
                        if redirects_followed >= max_redirects:
                            redirect_scope_status = (
                                "MAX_REDIRECTS_REACHED"
                            )
                            redirect_reason = (
                                f"Maximum redirect limit "
                                f"({max_redirects}) reached."
                            )

                            redirect_chain[-1]["scope_status"] = (
                                redirect_scope_status
                            )

                            return {
                                "website": url,
                                "final_url": current_url,
                                "scan_status": "REDIRECT_STOPPED",
                                "vulnerability_status": "NOT_SCANNED",
                                "reason": redirect_reason,
                                "redirect_detected": True,
                                "redirect_url": destination,
                                "redirect_scope_status": (
                                    redirect_scope_status
                                ),
                                "redirect_reason": redirect_reason,
                                "redirect_followed": redirect_followed,
                                "redirect_chain": redirect_chain,
                                **response_evidence,
                            }

                        # Step 9: Follow the validated destination.
                        redirect_chain[-1]["followed"] = True

                        redirect_followed = True
                        redirects_followed += 1
                        current_url = destination
                        visited_urls.add(current_url)

                        # The response context closes the old response
                        # before the next request begins.
                        continue

                    # Step 10: Analyse the final non-redirect response.
                    body = read_limited_response(response)

                    response_evidence = collect_response_evidence(
                        response,
                        body,
                    )

                    detection = identify_php(
                        dict(response.headers or {}),
                        body,
                    )

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
                                "Only weak PHP-related technology "
                                "indicators were found. PHP usage and "
                                "vulnerability status are unverified."
                            ),
                            "confirmed_vulnerability": False,
                            "matched_cves": 0,
                        }

                    else:

                        php_version = detection["php_version"]

                        version_status = check_version(php_version)
                        cve_matches = check_cves(php_version)

                        risk = analyze_risk(
                            version_status,
                            cve_matches,
                        )

                    # Step 11: Return the final scan result.
                    return {
                        "website": url,
                        "final_url": current_url,
                        "scan_status": "COMPLETED",

                        "redirect_detected": redirect_detected,
                        "redirect_url": redirect_url,
                        "redirect_scope_status": (
                            redirect_scope_status
                        ),
                        "redirect_reason": redirect_reason,
                        "redirect_followed": redirect_followed,
                        "redirect_chain": redirect_chain,

                        **response_evidence,

                        "vulnerability_status": version_status,
                        "cve_matches": cve_matches,
                        "risk": risk,
                    }

    except requests.RequestException as error:

        return {
            "website": url,
            "final_url": current_url,
            "scan_status": "ERROR",
            "vulnerability_status": "SCAN_ERROR",
            "error": str(error),
            "redirect_detected": redirect_detected,
            "redirect_followed": redirect_followed,
            "redirect_chain": redirect_chain,
            "vulnerability_confirmed": False,
        }
