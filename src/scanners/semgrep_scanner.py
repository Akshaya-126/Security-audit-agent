"""
Semgrep static-analysis scanner wrapper.

Runs Semgrep with the auto ruleset via subprocess and converts its JSON
output into a list of Finding dicts.  Falls back gracefully if Semgrep
is not on PATH.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.schemas.findings import Confidence, Finding, FindingStatus, Severity
from src.security.redaction import redact_string
from src.security.scan_limits import AGENT_TIMEOUT_SECONDS, MAX_FINDINGS_PER_AGENT

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Severity mapping
# ─────────────────────────────────────────────────────────────────────────────
_SEVERITY_MAP: Dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _categorize(rule_id: str) -> str:
    r = rule_id.lower()
    if any(x in r for x in ("sql", "sqli", "injection")):
        return "Injection"
    if any(x in r for x in ("xss", "cross-site", "script")):
        return "XSS"
    if any(x in r for x in ("auth", "authz", "authentication")):
        return "Authentication"
    if any(x in r for x in ("crypto", "hash", "encrypt", "ssl", "tls")):
        return "Cryptography"
    if any(x in r for x in ("path", "traversal", "directory")):
        return "Path Traversal"
    if any(x in r for x in ("command", "exec", "shell")):
        return "Command Injection"
    if any(x in r for x in ("deserializ", "pickle", "yaml")):
        return "Deserialization"
    if any(x in r for x in ("secret", "key", "token", "password", "cred")):
        return "Secrets"
    return "Security Misconfiguration"


def _get_recommendation(rule_id: str) -> str:
    r = rule_id.lower()
    if "sql" in r or "injection" in r:
        return "Use parameterized queries or an ORM to prevent SQL injection."
    if "xss" in r:
        return "Sanitize and HTML-encode all user-controlled data before rendering."
    if "command" in r or "exec" in r:
        return "Avoid shell=True. Pass arguments as a list to subprocess."
    if "path" in r or "traversal" in r:
        return "Validate and normalize file paths. Use os.path.realpath() / Path.resolve()."
    if "crypto" in r or "hash" in r:
        return "Use strong, up-to-date cryptographic algorithms (e.g., bcrypt, SHA-256)."
    if "secret" in r or "key" in r or "password" in r:
        return "Move secrets out of source code. Use environment variables or a vault."
    return "Review the flagged code and consult the Semgrep rule documentation."


def _parse_results(raw: Dict[str, Any], repo_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for result in raw.get("results", [])[:MAX_FINDINGS_PER_AGENT]:
        try:
            extra = result.get("extra", {})
            severity_str = extra.get("severity", "WARNING").upper()
            severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            file_path = result.get("path", "")
            try:
                file_path = str(Path(file_path).relative_to(repo_path))
            except ValueError:
                pass

            check_id = result.get("check_id", "unknown")
            message = extra.get("message", "No description available.")
            snippet = redact_string(extra.get("lines", "").strip())
            line = result.get("start", {}).get("line")

            human_title = check_id.split(".")[-1].replace("-", " ").replace("_", " ").title()

            finding = Finding(
                title=f"Semgrep: {human_title}",
                category=_categorize(check_id),
                severity=severity,
                confidence=Confidence.MEDIUM,
                file=file_path,
                line=line,
                description=message,
                evidence=snippet or f"Rule: {check_id}",
                recommendation=_get_recommendation(check_id),
                source="Semgrep",
                status=FindingStatus.MANUAL_REVIEW,
                rule_id=check_id,
            )
            findings.append(finding.to_dict())
        except Exception as exc:
            logger.warning("Failed to parse Semgrep result: %s", exc)

    return findings


def run_semgrep_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Run Semgrep on a local repository directory.

    Returns a list of Finding dicts, or an empty list if Semgrep is
    unavailable or no issues are found.
    """
    if not _semgrep_available():
        logger.warning("Semgrep not found in PATH — skipping static analysis.")
        return []

    logger.info("Running Semgrep on %s", repo_path)
    try:
        proc = subprocess.run(
            [
                "semgrep",
                "--config=auto",
                "--json",
                "--quiet",
                "--timeout=60",
                "--max-memory=1024",
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT_SECONDS,
        )

        # Exit code 1 means findings were found — that is normal.
        if proc.returncode not in (0, 1):
            logger.error(
                "Semgrep exited with code %d: %s",
                proc.returncode,
                proc.stderr[:400],
            )
            return []

        raw = json.loads(proc.stdout)
        findings = _parse_results(raw, repo_path)
        logger.info("Semgrep: %d findings", len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out after %d s", AGENT_TIMEOUT_SECONDS)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Could not parse Semgrep JSON: %s", exc)
        return []
    except Exception as exc:
        logger.exception("Unexpected Semgrep error: %s", exc)
        return []
