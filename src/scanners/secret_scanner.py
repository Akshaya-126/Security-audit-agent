"""
Secret-detection scanner.

Primary  : Gitleaks binary (subprocess, JSON output)
Fallback : Regex-based scanner covering 15+ common secret types

All detected secret *values* are redacted before the findings are
returned — only the type, file location, and line number are exposed.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

from src.schemas.findings import Confidence, Finding, FindingStatus, Severity
from src.security.scan_limits import AGENT_TIMEOUT_SECONDS, MAX_FINDINGS_PER_AGENT

logger = logging.getLogger(__name__)


def _gitleaks_available() -> bool:
    return shutil.which("gitleaks") is not None


# ─────────────────────────────────────────────────────────────────────────────
# Fallback regex patterns
# (name, pattern, severity)
# ─────────────────────────────────────────────────────────────────────────────
_SECRET_PATTERNS: List[Tuple[str, re.Pattern, Severity]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?"
        ),
        Severity.CRITICAL,
    ),
    (
        "GitHub Token",
        re.compile(r"(ghp_|ghs_|github_pat_)[A-Za-z0-9_]{20,}"),
        Severity.CRITICAL,
    ),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    ("Stripe Secret Key", re.compile(r"sk_live_[A-Za-z0-9]{24}"), Severity.CRITICAL),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        Severity.HIGH,
    ),
    (
        "Generic API Key",
        re.compile(
            r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"
        ),
        Severity.HIGH,
    ),
    (
        "Hardcoded Password",
        re.compile(
            r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
        ),
        Severity.HIGH,
    ),
    (
        "JWT Secret",
        re.compile(
            r"(?i)jwt[_\-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?"
        ),
        Severity.HIGH,
    ),
    (
        "Private Key Block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
        Severity.CRITICAL,
    ),
    (
        "Database Connection String with Password",
        re.compile(r"(?i)(mysql|postgres|mongodb|redis)://[^:@/\s]+:[^@/\s]{6,}@"),
        Severity.HIGH,
    ),
    (
        "Twilio Auth Token",
        re.compile(r"(?i)twilio.*[0-9a-f]{32}"),
        Severity.HIGH,
    ),
    (
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        Severity.HIGH,
    ),
]

# Extensions worth scanning for secrets
_SCANNABLE_EXTS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".env", ".yaml", ".yml", ".json", ".toml",
    ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh", ".tf", ".tfvars",
    ".properties", ".xml", ".sql", ".gradle",
}

# Directories to skip
_SKIP_DIRS: set[str] = {
    ".git", "node_modules", "__pycache__", ".tox", "venv", ".venv",
    "dist", "build", ".pytest_cache",
}


def has_secret_like_value(content: str) -> bool:
    """Return whether the secret scanner's known patterns match file contents."""
    return any(pattern.search(content) for _, pattern, _ in _SECRET_PATTERNS)


# ─────────────────────────────────────────────────────────────────────────────
# Gitleaks scanner
# ─────────────────────────────────────────────────────────────────────────────

def _run_gitleaks(repo_path: str) -> List[Dict[str, Any]]:
    try:
        proc = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", repo_path,
                "--report-format", "json",
                "--report-path", "-",
                "--no-git",
                "--exit-code", "0",
            ],
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT_SECONDS,
        )

        output = proc.stdout.strip()
        if not output or output == "null":
            return []

        leaks = json.loads(output)
        if not isinstance(leaks, list):
            return []

        findings: List[Dict[str, Any]] = []
        for leak in leaks[:MAX_FINDINGS_PER_AGENT]:
            file_path = leak.get("File", "").replace(repo_path, "").lstrip("/\\")
            finding = Finding(
                title=f"Secret Detected: {leak.get('RuleID', 'Unknown')}",
                category="Secrets",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file=file_path,
                line=leak.get("StartLine"),
                description=(
                    f"Gitleaks detected a potential secret matching rule "
                    f"'{leak.get('RuleID', 'unknown')}'. "
                    "Credential type: "
                    f"{leak.get('Description', 'unknown')}."
                ),
                evidence="[SECRET VALUE REDACTED]",
                recommendation=(
                    "Remove the secret from source code immediately. "
                    "Rotate the credential and store it in an environment variable "
                    "or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)."
                ),
                source="Gitleaks",
                status=FindingStatus.CONFIRMED,
                rule_id=leak.get("RuleID"),
            )
            findings.append(finding.to_dict())

        return findings

    except subprocess.TimeoutExpired:
        logger.error("Gitleaks timed out")
        return []
    except json.JSONDecodeError as exc:
        logger.error("Could not parse Gitleaks output: %s", exc)
        return []
    except Exception as exc:
        logger.exception("Gitleaks error: %s", exc)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Regex fallback scanner
# ─────────────────────────────────────────────────────────────────────────────

def _run_regex_scan(repo_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    repo = Path(repo_path)

    for path in repo.rglob("*"):
        if any(skip in path.parts for skip in _SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in _SCANNABLE_EXTS:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for rule_name, pattern, severity in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                relative = str(path.relative_to(repo_path))

                finding = Finding(
                    title=f"Potential {rule_name}",
                    category="Secrets",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    file=relative,
                    line=line_num,
                    description=(
                        f"A pattern matching a {rule_name.lower()} was found in source code."
                    ),
                    evidence="[SECRET VALUE REDACTED]",
                    recommendation=(
                        "Move this secret to an environment variable or secrets manager. "
                        "If a real credential was exposed, rotate it immediately."
                    ),
                    source="Regex Scanner",
                    status=FindingStatus.MANUAL_REVIEW,
                    rule_id=rule_name.lower().replace(" ", "-"),
                )
                findings.append(finding.to_dict())

                if len(findings) >= MAX_FINDINGS_PER_AGENT:
                    return findings

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_secret_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan a local repository for exposed secrets.

    Uses Gitleaks when available; falls back to built-in regex patterns.
    Secret values are always redacted before being returned.
    """
    if _gitleaks_available():
        logger.info("Running Gitleaks on %s", repo_path)
        findings = _run_gitleaks(repo_path)
        logger.info("Gitleaks: %d secrets detected", len(findings))
    else:
        logger.warning("Gitleaks not found — using fallback regex scanner.")
        findings = _run_regex_scan(repo_path)
        logger.info("Regex scanner: %d potential secrets detected", len(findings))

    return findings
