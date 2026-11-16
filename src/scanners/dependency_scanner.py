"""
Dependency vulnerability scanner.

Primary  : OSV-Scanner binary (subprocess, JSON output)
Fallback : Direct OSV REST API queries via httpx for requirements.txt
           and package.json files.

Identifies known CVEs and OSV advisories in project dependencies.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from src.schemas.findings import Confidence, Finding, FindingStatus, Severity
from src.security.scan_limits import (
    AGENT_TIMEOUT_SECONDS,
    HTTP_REQUEST_TIMEOUT,
    MAX_FINDINGS_PER_AGENT,
)

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"


def _osv_scanner_available() -> bool:
    return shutil.which("osv-scanner") is not None


# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cvss_to_severity(score_str: str) -> Optional[Severity]:
    """Convert a CVSS numeric string to a Severity enum value."""
    # CVSS strings can be "CVSS:3.1/AV:N/AC:L/..." — try the numeric part
    numeric = re.search(r"(\d+(?:\.\d+)?)", score_str)
    if not numeric:
        return None
    value = float(numeric.group(1))
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _get_severity(vuln: Dict[str, Any]) -> Severity:
    for entry in vuln.get("severity", []):
        sev = _cvss_to_severity(entry.get("score", ""))
        if sev:
            return sev
    return Severity.MEDIUM


def _get_fixed_versions(vuln: Dict[str, Any]) -> str:
    versions: List[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    versions.append(event["fixed"])
    return ", ".join(versions[:3]) if versions else "No fix available"


# ─────────────────────────────────────────────────────────────────────────────
# OSV-Scanner binary
# ─────────────────────────────────────────────────────────────────────────────

def _run_osv_binary(repo_path: str) -> List[Dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["osv-scanner", "--recursive", "--format=json", repo_path],
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT_SECONDS,
        )
        output = proc.stdout.strip()
        if not output:
            return []
        raw = json.loads(output)
        return _parse_osv_output(raw)
    except subprocess.TimeoutExpired:
        logger.error("OSV-Scanner timed out")
        return []
    except json.JSONDecodeError as exc:
        logger.error("Could not parse OSV-Scanner output: %s", exc)
        return []
    except Exception as exc:
        logger.exception("OSV-Scanner error: %s", exc)
        return []


def _parse_osv_output(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for result in raw.get("results", []):
        source_path = result.get("source", {}).get("path", "")
        for pkg_entry in result.get("packages", []):
            package = pkg_entry.get("package", {})
            pkg_name = package.get("name", "")
            pkg_version = package.get("version", "")

            for vuln in pkg_entry.get("vulnerabilities", []):
                if len(findings) >= MAX_FINDINGS_PER_AGENT:
                    return findings

                vuln_id = vuln.get("id", "unknown")
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                severity = _get_severity(vuln)
                fixed = _get_fixed_versions(vuln)
                summary = vuln.get("summary", "Known vulnerability.")
                details = vuln.get("details", "")
                description = f"{summary}\n\n{details}".strip()[:600]

                finding = Finding(
                    title=f"Vulnerable Dependency: {pkg_name} ({vuln_id})",
                    category="Vulnerable Dependency",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    file=source_path,
                    description=description,
                    evidence=f"{pkg_name}=={pkg_version} → {vuln_id}",
                    recommendation=f"Upgrade {pkg_name} to {fixed}.",
                    source="OSV-Scanner",
                    status=FindingStatus.CONFIRMED,
                    cve_id=cve_id,
                    osv_id=vuln_id,
                    package=pkg_name,
                    installed_version=pkg_version,
                    fixed_version=fixed,
                )
                findings.append(finding.to_dict())

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Fallback: OSV API + manifest parser
# ─────────────────────────────────────────────────────────────────────────────

def _query_osv_api(name: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    try:
        with httpx.Client(timeout=HTTP_REQUEST_TIMEOUT) as client:
            resp = client.post(OSV_API_URL, json=payload)
            resp.raise_for_status()
            return resp.json().get("vulns", [])
    except Exception as exc:
        logger.warning("OSV API query failed for %s==%s: %s", name, version, exc)
        return []


def _parse_requirements_txt(path: Path) -> List[Tuple[str, str]]:
    packages: List[Tuple[str, str]] = []
    pattern = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#\[]+)")
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(line)
            if m:
                packages.append((m.group(1), m.group(2)))
    except Exception:
        pass
    return packages


def _parse_package_json(path: Path) -> List[Tuple[str, str]]:
    packages: List[Tuple[str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        for section in ("dependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                # Strip semver prefixes (^, ~, >=, etc.)
                clean = re.sub(r"[^0-9.]", "", version.split(" ")[0])
                if clean:
                    packages.append((name, clean))
    except Exception:
        pass
    return packages


_MANIFEST_CONFIGS: Dict[str, Any] = {
    "requirements.txt": ("PyPI", _parse_requirements_txt),
    "package.json": ("npm", _parse_package_json),
}


def _fallback_scan(repo_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    repo = Path(repo_path)
    skip = {".git", "node_modules", "__pycache__", "venv", ".venv"}

    for manifest_name, (ecosystem, parser) in _MANIFEST_CONFIGS.items():
        for manifest_path in repo.rglob(manifest_name):
            if any(s in manifest_path.parts for s in skip):
                continue

            packages = parser(manifest_path)
            relative = str(manifest_path.relative_to(repo_path))

            for name, version in packages:
                vulns = _query_osv_api(name, version, ecosystem)
                for vuln in vulns:
                    if len(findings) >= MAX_FINDINGS_PER_AGENT:
                        return findings

                    vuln_id = vuln.get("id", "unknown")
                    aliases = vuln.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                    summary = vuln.get("summary", "Known vulnerability.")

                    finding = Finding(
                        title=f"Vulnerable Package: {name} ({vuln_id})",
                        category="Vulnerable Dependency",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file=relative,
                        description=summary,
                        evidence=f"{name}=={version} has known vulnerability {vuln_id}",
                        recommendation=f"Upgrade {name} to a patched version. See {vuln_id}.",
                        source="OSV API",
                        status=FindingStatus.CONFIRMED,
                        cve_id=cve_id,
                        osv_id=vuln_id,
                        package=name,
                        installed_version=version,
                    )
                    findings.append(finding.to_dict())

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_dependency_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan a repository for vulnerable dependencies.

    Uses OSV-Scanner when available; falls back to direct OSV API queries.
    """
    if _osv_scanner_available():
        logger.info("Running OSV-Scanner on %s", repo_path)
        findings = _run_osv_binary(repo_path)
        logger.info("OSV-Scanner: %d vulnerabilities", len(findings))
    else:
        logger.warning("OSV-Scanner not found — querying OSV API directly.")
        findings = _fallback_scan(repo_path)
        logger.info("OSV API fallback: %d vulnerabilities", len(findings))

    return findings
