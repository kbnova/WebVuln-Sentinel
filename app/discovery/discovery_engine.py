
"""Collect and validate authorised website discovery results."""

import ipaddress
import re
from urllib.parse import urlsplit


def normalize_domain(domain):
    """Normalize and validate a DNS hostname."""
    if not isinstance(domain, str):
        return None

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass

    labels = domain.split(".")

    if len(labels) < 2:
        return None

    if any(
        not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            label
        )
        for label in labels
    ):
        return None

    return domain


def is_domain_authorized(domain, scope):
    """Check whether a domain is within the configured scope."""
    domain = normalize_domain(domain)

    if domain is None:
        return False

    for allowed in scope.get("authorized_domains", []):
        allowed = normalize_domain(allowed)

        if allowed is None:
            continue

        if domain == allowed:
            return True

        if (
            scope.get("allow_subdomains", False)
            and domain.endswith("." + allowed)
        ):
            return True

    return False


def is_candidate_within_domain(website, authorized_domain, scope):
    """Validate a discovered URL against the authorized root domain."""
    if not isinstance(website, str):
        return False

    try:
        parsed = urlsplit(website.strip())

        if parsed.scheme.lower() not in ("http", "https"):
            return False

        if not parsed.netloc:
            return False

        if parsed.username or parsed.password:
            return False

        _ = parsed.port

        hostname = normalize_domain(parsed.hostname)
        requested_domain = normalize_domain(authorized_domain)

        if hostname is None or requested_domain is None:
            return False

        for allowed in scope.get("authorized_domains", []):
            root = normalize_domain(allowed)

            if root is None:
                continue

            request_is_in_root = (
                requested_domain == root
                or (
                    scope.get("allow_subdomains", False)
                    and requested_domain.endswith("." + root)
                )
            )

            if not request_is_in_root:
                continue

            candidate_is_in_root = (
                hostname == root
                or (
                    scope.get("allow_subdomains", False)
                    and hostname.endswith("." + root)
                )
            )

            if candidate_is_in_root:
                return True

        return False

    except (ValueError, TypeError):
        return False


class DiscoveryEngine:
    """Coordinate passive discovery providers safely."""

    def __init__(self, providers=None, scope=None):
        self.providers = providers or []
        self.scope = scope or {}

    def discover(self, query, limit=10):
        """Discover and validate hostnames within an authorized domain."""

        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("Limit must be an integer.")

        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000.")

        domain = normalize_domain(query)

        if domain is None:
            raise ValueError("A valid domain name is required.")

        if not is_domain_authorized(domain, self.scope):
            raise PermissionError(
                "Discovery domain is not in the authorized scope."
            )

        results = []
        seen = set()

        for provider in self.providers:
            remaining = limit - len(results)

            if remaining <= 0:
                break

            candidates = provider.search(
                query=domain,
                limit=remaining
            )

            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue

                website = candidate.get("website")

                if not is_candidate_within_domain(
                    website, domain, self.scope
                ):
                    continue

                website = website.strip()
                parsed = urlsplit(website)

                normalized_url = (
                    f"{parsed.scheme.lower()}://"
                    f"{parsed.netloc.lower()}"
                    f"{parsed.path or '/'}"
                    f"?{parsed.query}"
                )

                if normalized_url in seen:
                    continue

                seen.add(normalized_url)

                results.append({
                    **candidate,
                    "website": website
                })

                if len(results) >= limit:
                    break

        return results
