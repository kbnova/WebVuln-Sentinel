"""Passive hostname discovery using Certificate Transparency records."""

import ipaddress
import re

import requests

from app.discovery.base import DiscoveryProvider


class CrtShProvider(DiscoveryProvider):
    """Discover subdomains from public crt.sh certificate records."""

    API_URL = "https://crt.sh/"
    USER_AGENT = "WebVuln-Sentinel/1.0"

    def search(self, query, limit=10):
        """
        Discover certificate-listed subdomains of an authorised domain.

        This only retrieves public certificate records. It does not
        contact discovered websites or test them for vulnerabilities.
        """

        if not isinstance(query, str):
            raise ValueError("A domain name is required.")

        domain = query.strip().lower().rstrip(".")

        if not domain or len(domain) > 253 or "*" in domain:
            raise ValueError("Invalid domain name.")

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("Invalid domain name.") from error

        labels = domain.split(".")

        if (
            len(labels) < 2
            or any(
                not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                    label
                )
                for label in labels
            )
        ):
            raise ValueError("Invalid domain name.")

        try:
            ipaddress.ip_address(domain)
            raise ValueError("IP addresses are not accepted.")
        except ValueError as error:
            if str(error) == "IP addresses are not accepted.":
                raise

        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("Limit must be an integer.")

        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000.")

        response = requests.get(
            self.API_URL,
            params={
                "q": f"%.{domain}",
                "output": "json"
            },
            headers={"User-Agent": self.USER_AGENT},
            timeout=30
        )

        response.raise_for_status()

        try:
            records = response.json()
        except ValueError as error:
            raise RuntimeError(
                "crt.sh returned an invalid JSON response."
            ) from error

        if not isinstance(records, list):
            raise RuntimeError(
                "Unexpected response format from crt.sh."
            )

        discovered = {}

        for record in records:
            if not isinstance(record, dict):
                continue

            names = record.get("name_value", "")

            if not isinstance(names, str):
                continue

            for raw_name in names.splitlines():
                hostname = raw_name.strip().lower().rstrip(".")

                if hostname.startswith("*."):
                    hostname = hostname[2:]

                if not hostname or len(hostname) > 253:
                    continue

                try:
                    hostname = hostname.encode("idna").decode("ascii")
                except UnicodeError:
                    continue

                # Keep only hostnames belonging to the requested domain.
                if not hostname.endswith("." + domain):
                    continue

                if hostname == domain:
                    continue

                if hostname in discovered:
                    continue

                discovered[hostname] = {
                    "website": f"https://{hostname}",
                    "source": "crt.sh",
                    "evidence": "Certificate Transparency record",
                    "php_detected": None,
                    "assessment": "NOT_ASSESSED"
                }

                if len(discovered) >= limit:
                    break

            if len(discovered) >= limit:
                break

        return list(discovered.values())