"""
Website security scanner.

Performs a passive security assessment of a live website using httpx:
  - HTTPS availability
  - TLS certificate validity and expiry
  - HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
  - Cookie security attributes (Secure, HttpOnly, SameSite)
  - Server and technology header disclosure
  - Basic CSP quality checks (unsafe-inline, unsafe-eval)

No active exploitation or fuzzing is performed.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

from src.schemas.findings import Confidence, Finding, FindingStatus, Severity
from src.security.scan_limits import HTTP_REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Security header definitions
# ─────────────────────────────────────────────────────────────────────────────
_SECURITY_HEADERS: List[Dict[str, Any]] = [
    {
        "header": "Strict-Transport-Security",
        "severity": Severity.HIGH,
        "category": "Transport Security",
        "description": (
            "HTTP Strict Transport Security (HSTS) instructs browsers to only "
            "connect via HTTPS. Without it, users are vulnerable to SSL-stripping attacks."
        ),
        "recommendation": (
            "Add header: Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload"
        ),
    },
    {
        "header": "Content-Security-Policy",
        "severity": Severity.HIGH,
        "category": "XSS Prevention",
        "description": (
            "Content Security Policy restricts which resources the browser may load, "
            "significantly reducing the risk of cross-site scripting (XSS)."
        ),
        "recommendation": (
            "Define a CSP policy, e.g.: "
            "Content-Security-Policy: default-src 'self'; script-src 'self'"
        ),
    },
    {
        "header": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "category": "Clickjacking",
        "description": (
            "X-Frame-Options prevents the page from being embedded in iframes "
            "on other domains, mitigating clickjacking attacks."
        ),
        "recommendation": "Add header: X-Frame-Options: DENY",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "category": "MIME Sniffing",
        "description": (
            "X-Content-Type-Options: nosniff prevents browsers from MIME-type "
            "sniffing, which can be exploited to execute scripts."
        ),
        "recommendation": "Add header: X-Content-Type-Options: nosniff",
    },
    {
        "header": "Referrer-Policy",
        "severity": Severity.LOW,
        "category": "Information Disclosure",
        "description": (
            "Referrer-Policy controls how much referrer information is sent with "
            "requests, reducing the risk of leaking sensitive URL parameters."
        ),
        "recommendation": (
            "Add header: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    },
    {
        "header": "Permissions-Policy",
        "severity": Severity.LOW,
        "category": "Feature Policy",
        "description": (
            "Permissions-Policy restricts access to powerful browser APIs "
            "(camera, microphone, geolocation) that may be abused by injected scripts."
        ),
        "recommendation": (
            "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ),
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# TLS certificate check
# ─────────────────────────────────────────────────────────────────────────────

def _check_tls_certificate(hostname: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "valid": False, "days_remaining": None, "expires_at": None,
        "subject": None, "issuer": None, "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days = (expiry - datetime.now(timezone.utc)).days
                    result.update(
                        valid=days > 0,
                        days_remaining=days,
                        expires_at=expiry.isoformat(),
                    )
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["subject"] = subject.get("commonName")
                result["issuer"] = issuer.get("organizationName")
    except ssl.SSLError as exc:
        result["error"] = f"TLS error: {exc}"
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Cookie analysis
# ─────────────────────────────────────────────────────────────────────────────

def _check_cookies(response: httpx.Response, url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for cookie in response.cookies.jar:
        name = cookie.name
        secure = bool(cookie.secure)
        cookie_str = str(cookie).lower()
        http_only = "httponly" in cookie_str
        same_site = None
        for part in cookie_str.split(";"):
            part = part.strip()
            if part.startswith("samesite="):
                same_site = part.split("=", 1)[1].strip()

        if not secure:
            findings.append(Finding(
                title=f"Cookie Missing Secure Flag: {name}",
                category="Cookie Security",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                url=url,
                description=(
                    f"Cookie '{name}' does not have the Secure flag set. "
                    "It may be transmitted over unencrypted HTTP connections."
                ),
                evidence=f"Set-Cookie: {name}=... (Secure flag absent)",
                recommendation=(
                    f"Set the Secure attribute on cookie '{name}' so it is "
                    "only transmitted over HTTPS."
                ),
                source="HTTPX",
                status=FindingStatus.CONFIRMED,
            ).to_dict())

        if not http_only:
            findings.append(Finding(
                title=f"Cookie Missing HttpOnly Flag: {name}",
                category="Cookie Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=url,
                description=(
                    f"Cookie '{name}' is accessible via JavaScript (HttpOnly flag absent). "
                    "An XSS attack could steal this cookie."
                ),
                evidence=f"Set-Cookie: {name}=... (HttpOnly flag absent)",
                recommendation=(
                    f"Set the HttpOnly attribute on cookie '{name}' to prevent "
                    "JavaScript access."
                ),
                source="HTTPX",
                status=FindingStatus.CONFIRMED,
            ).to_dict())

        if not same_site:
            findings.append(Finding(
                title=f"Cookie Missing SameSite Attribute: {name}",
                category="Cookie Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=url,
                description=(
                    f"Cookie '{name}' has no SameSite attribute, leaving it "
                    "potentially vulnerable to cross-site request forgery (CSRF)."
                ),
                evidence=f"Set-Cookie: {name}=... (SameSite absent)",
                recommendation=(
                    f"Add SameSite=Strict or SameSite=Lax to cookie '{name}'."
                ),
                source="HTTPX",
                status=FindingStatus.CONFIRMED,
            ).to_dict())

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_website_scan(website_url: str) -> List[Dict[str, Any]]:
    """
    Passively scan a website for observable security issues.

    Returns a list of Finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(website_url)
    hostname = parsed.hostname or ""

    logger.info("Starting website scan: %s", website_url)

    # ── HTTPS check ───────────────────────────────────────────────────────────
    if parsed.scheme != "https":
        findings.append(Finding(
            title="Website Not Served Over HTTPS",
            category="Transport Security",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            url=website_url,
            description="The website is served over plain HTTP. All traffic is unencrypted.",
            evidence=f"URL scheme: '{parsed.scheme}'",
            recommendation=(
                "Configure a TLS certificate and redirect all HTTP traffic to HTTPS. "
                "Let's Encrypt provides free certificates."
            ),
            source="HTTPX",
            status=FindingStatus.CONFIRMED,
        ).to_dict())

    # ── HTTP request ──────────────────────────────────────────────────────────
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=HTTP_REQUEST_TIMEOUT,
            verify=True,
        ) as client:
            response = client.get(website_url)

        headers = {k.lower(): v for k, v in response.headers.items()}

        # ── Security headers ──────────────────────────────────────────────────
        for hdr in _SECURITY_HEADERS:
            if hdr["header"].lower() not in headers:
                findings.append(Finding(
                    title=f"Missing Security Header: {hdr['header']}",
                    category=hdr["category"],
                    severity=hdr["severity"],
                    confidence=Confidence.HIGH,
                    url=website_url,
                    description=hdr["description"],
                    evidence=f"HTTP response does not include '{hdr['header']}' header.",
                    recommendation=hdr["recommendation"],
                    source="HTTPX",
                    status=FindingStatus.CONFIRMED,
                ).to_dict())

        # ── CSP quality ───────────────────────────────────────────────────────
        csp = headers.get("content-security-policy", "")
        if csp:
            for directive in ("unsafe-inline", "unsafe-eval"):
                if directive in csp:
                    findings.append(Finding(
                        title=f"Weak CSP: '{directive}' Allowed",
                        category="XSS Prevention",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        url=website_url,
                        description=(
                            f"The Content-Security-Policy includes '{directive}', "
                            "weakening protection against XSS attacks."
                        ),
                        evidence=f"Content-Security-Policy: {csp[:300]}",
                        recommendation=(
                            f"Remove '{directive}' from your CSP. "
                            "Use nonces or hashes for inline scripts instead."
                        ),
                        source="HTTPX",
                        status=FindingStatus.CONFIRMED,
                    ).to_dict())

        # ── HSTS quality ──────────────────────────────────────────────────────
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if m and int(m.group(1)) < 31_536_000:
                findings.append(Finding(
                    title="Short HSTS max-age (< 1 year)",
                    category="Transport Security",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    url=website_url,
                    description=(
                        f"HSTS max-age is {m.group(1)} seconds, which is less than "
                        "the recommended minimum of 31536000 (1 year)."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation=(
                        "Set max-age to at least 31536000 and add includeSubDomains."
                    ),
                    source="HTTPX",
                    status=FindingStatus.CONFIRMED,
                ).to_dict())

        # ── Cookie checks ─────────────────────────────────────────────────────
        findings.extend(_check_cookies(response, website_url))

        # ── Server header disclosure ──────────────────────────────────────────
        server = headers.get("server", "")
        if server and any(c.isdigit() for c in server):
            findings.append(Finding(
                title="Server Version Disclosure",
                category="Information Disclosure",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                url=website_url,
                description=(
                    "The Server response header reveals version information "
                    "that could help attackers identify known vulnerabilities."
                ),
                evidence=f"Server: {server}",
                recommendation=(
                    "Configure your web server to suppress version numbers from the "
                    "Server header (e.g., ServerTokens Prod in Apache)."
                ),
                source="HTTPX",
                status=FindingStatus.CONFIRMED,
            ).to_dict())

        # ── X-Powered-By disclosure ───────────────────────────────────────────
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            findings.append(Finding(
                title="Technology Disclosure via X-Powered-By",
                category="Information Disclosure",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                url=website_url,
                description=(
                    "The X-Powered-By header reveals the backend technology stack."
                ),
                evidence=f"X-Powered-By: {powered_by}",
                recommendation="Remove or suppress the X-Powered-By response header.",
                source="HTTPX",
                status=FindingStatus.CONFIRMED,
            ).to_dict())

    except httpx.SSLError as exc:
        findings.append(Finding(
            title="TLS/SSL Certificate Error",
            category="Transport Security",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            url=website_url,
            description=f"The website's TLS certificate is invalid or untrusted: {exc}",
            evidence=str(exc)[:300],
            recommendation=(
                "Install a valid TLS certificate from a trusted CA. "
                "Let's Encrypt provides free certificates."
            ),
            source="HTTPX",
            status=FindingStatus.CONFIRMED,
        ).to_dict())

    except httpx.RequestError as exc:
        logger.error("HTTP request failed for %s: %s", website_url, exc)

    # ── TLS certificate expiry ────────────────────────────────────────────────
    if parsed.scheme == "https" and hostname:
        cert = _check_tls_certificate(hostname)
        days = cert.get("days_remaining")
        if days is not None and days < 30:
            sev = Severity.HIGH if days < 7 else Severity.MEDIUM
            findings.append(Finding(
                title=f"TLS Certificate Expiring in {days} Day(s)",
                category="Transport Security",
                severity=sev,
                confidence=Confidence.HIGH,
                url=website_url,
                description=(
                    f"The TLS certificate for {hostname} expires in {days} day(s). "
                    "Expiry will cause browsers to show a security warning."
                ),
                evidence=f"Certificate expires: {cert.get('expires_at')}",
                recommendation="Renew the TLS certificate before it expires.",
                source="TLS Check",
                status=FindingStatus.CONFIRMED,
            ).to_dict())

    logger.info("Website scan: %d issues found", len(findings))
    return findings
