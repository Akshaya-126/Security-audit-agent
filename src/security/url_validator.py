"""
URL validation and SSRF-prevention utilities.

Blocks private/loopback IP ranges, cloud metadata endpoints, and other
reserved addresses. Validates GitHub and website URL formats.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from typing import Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Blocked IP networks (private, loopback, link-local, reserved, cloud metadata)
# ─────────────────────────────────────────────────────────────────────────────
_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Cloud metadata and internal service hostnames to block
_BLOCKED_HOSTNAMES: set[str] = {
    "metadata.google.internal",
    "169.254.169.254",             # AWS / GCP metadata IP
    "metadata.aws.amazonaws.com",
    "metadata.azure.com",
    "localhost",
    "broadcasthost",
}

# Allowed URL schemes
_ALLOWED_SCHEMES: set[str] = {"http", "https"}

# GitHub URL pattern
_GITHUB_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


class URLValidationError(ValueError):
    """Raised when a URL fails safety validation."""


def _is_ip_blocked(ip_str: str) -> bool:
    """Return True if the given IP string falls in a blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in network for network in _BLOCKED_NETWORKS)


def _resolve_and_check(hostname: str) -> None:
    """
    DNS-resolve a hostname and raise URLValidationError if any resolved
    address is in a blocked (private/reserved) range.
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise URLValidationError(
            f"DNS resolution failed for '{hostname}': {exc}"
        ) from exc

    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        if _is_ip_blocked(ip_str):
            raise URLValidationError(
                f"Hostname '{hostname}' resolves to blocked IP {ip_str} "
                "(private/reserved address)."
            )


def validate_url(url: str, *, check_dns: bool = True) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL for safety.

    Returns
    -------
    (is_valid, error_message)  —  error_message is None when valid.
    """
    if not url or not url.strip():
        return False, "URL is empty."

    try:
        parsed = urllib.parse.urlparse(url.strip())
    except Exception as exc:
        return False, f"Failed to parse URL: {exc}"

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return False, (
            f"URL scheme '{parsed.scheme}' is not allowed. Use http or https."
        )

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname."

    # Block cloud metadata and known internal hostnames
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return False, f"Hostname '{hostname}' is blocked."

    # Block raw IP addresses (must supply a domain name)
    try:
        # If this succeeds, it's a literal IP address
        ipaddress.ip_address(hostname)
        return False, (
            f"Direct IP addresses are not permitted. Use a domain name."
        )
    except ValueError:
        pass  # It is a hostname — continue

    # DNS resolution + private-IP check
    if check_dns:
        try:
            _resolve_and_check(hostname)
        except URLValidationError as exc:
            return False, str(exc)

    return True, None


def validate_github_url(
    url: str,
) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    Validate a GitHub repository URL.

    Returns
    -------
    (is_valid, error_message, owner, repo)
    """
    if not url or not url.strip():
        return False, "GitHub URL is empty.", None, None

    match = _GITHUB_URL_RE.match(url.strip())
    if not match:
        return (
            False,
            "Invalid GitHub URL. Expected: https://github.com/<owner>/<repo>",
            None,
            None,
        )

    owner, repo = match.group(1), match.group(2)

    is_valid, error = validate_url(url, check_dns=True)
    if not is_valid:
        return False, error, None, None

    return True, None, owner, repo


def validate_website_url(url: str) -> Tuple[bool, Optional[str]]:
    """Validate a website URL for scanning."""
    return validate_url(url, check_dns=True)
