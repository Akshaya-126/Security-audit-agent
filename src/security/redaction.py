"""
Secret redaction utilities.

Scrubs sensitive values (API keys, passwords, tokens, private keys) from
scanner outputs before the findings reach the frontend or reports.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


# ─────────────────────────────────────────────────────────────────────────────
# Redaction patterns
# Each entry: (compiled_regex, replacement_string)
# ─────────────────────────────────────────────────────────────────────────────
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "***AWS_KEY_REDACTED***"),
    # AWS Secret Access Key
    (
        re.compile(
            r"(?i)(aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*)['\"]?([A-Za-z0-9+/]{40})['\"]?",
        ),
        r"\1***REDACTED***",
    ),
    # GitHub personal access tokens
    (
        re.compile(r"(ghp_|ghs_|github_pat_)[A-Za-z0-9_]{20,}"),
        "***GITHUB_TOKEN_REDACTED***",
    ),
    # Google API keys
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "***GOOGLE_API_KEY_REDACTED***"),
    # Stripe secret keys
    (re.compile(r"sk_live_[A-Za-z0-9]{24}"), "***STRIPE_SECRET_REDACTED***"),
    # Slack tokens
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "***SLACK_TOKEN_REDACTED***"),
    # Generic API key / secret assignment
    (
        re.compile(
            r"(?i)(api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{16,})['\"]?"
        ),
        r"\1=***REDACTED***",
    ),
    # Hardcoded passwords
    (
        re.compile(
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]"
        ),
        r"\1=***REDACTED***",
    ),
    # JWT secrets
    (
        re.compile(
            r"(?i)(jwt[_\-]?secret|secret[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?"
        ),
        r"\1=***REDACTED***",
    ),
    # Bearer tokens
    (
        re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)"),
        "Bearer ***REDACTED***",
    ),
    # Connection strings with embedded passwords
    (
        re.compile(r"(?i)(https?://[^:@/\s]+):([^@/\s]{3,})@"),
        r"\1:***REDACTED***@",
    ),
    # PEM private key blocks
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "***PRIVATE_KEY_REDACTED***",
    ),
]


def redact_string(text: str) -> str:
    """Apply all redaction patterns to a string and return the scrubbed result."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact sensitive values in a finding dictionary."""
    result: Dict[str, Any] = {}
    for key, value in finding.items():
        if isinstance(value, str):
            result[key] = redact_string(value)
        elif isinstance(value, dict):
            result[key] = redact_finding(value)
        elif isinstance(value, list):
            result[key] = [
                redact_finding(item)
                if isinstance(item, dict)
                else redact_string(item)
                if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result


def redact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Redact all findings in a list."""
    return [redact_finding(f) for f in findings]
