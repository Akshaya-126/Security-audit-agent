"""
Infrastructure and configuration security scanner.

Primary  : Checkov (IaC scanner — Terraform, Docker, K8s, GHA, etc.)
Supplemental : Custom rules for Dockerfile best-practice violations.

Falls back to custom rules only when Checkov is not installed.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List

from src.schemas.findings import Confidence, Finding, FindingStatus, Severity
from src.security.scan_limits import AGENT_TIMEOUT_SECONDS, MAX_FINDINGS_PER_AGENT

logger = logging.getLogger(__name__)


def _checkov_available() -> bool:
    return shutil.which("checkov") is not None


# ─────────────────────────────────────────────────────────────────────────────
# Checkov integration
# ─────────────────────────────────────────────────────────────────────────────

def _infer_severity(check_id: str) -> Severity:
    """Infer Severity from a Checkov check_id."""
    # Checkov doesn't expose per-check severity in older versions
    # Map known high-risk IDs; default to MEDIUM
    critical_ids = {
        "CKV_AWS_19", "CKV_AWS_20", "CKV_AWS_21",  # S3 public access
        "CKV_DOCKER_2",                               # No root user
        "CKV_K8S_30",                                 # Privileged container
    }
    high_ids = {
        "CKV_AWS_8", "CKV_AWS_18", "CKV_AWS_57",
        "CKV_GCP_1", "CKV_AZURE_1",
    }
    if check_id in critical_ids:
        return Severity.CRITICAL
    if check_id in high_ids:
        return Severity.HIGH
    return Severity.MEDIUM


def _categorize_check(check_id: str) -> str:
    if "DOCKER" in check_id:
        return "Container Security"
    if "K8S" in check_id:
        return "Kubernetes Security"
    if "GHA" in check_id:
        return "GitHub Actions Security"
    if "AWS" in check_id or "GCP" in check_id or "AZURE" in check_id:
        return "Cloud Security"
    if "TF" in check_id:
        return "Terraform Security"
    return "Infrastructure Security"


def _parse_checkov_output(raw: Any, repo_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    results_list = raw if isinstance(raw, list) else [raw]

    for framework_result in results_list:
        if not isinstance(framework_result, dict):
            continue

        failed = framework_result.get("results", {}).get("failed_checks", [])
        for check in failed:
            if len(findings) >= MAX_FINDINGS_PER_AGENT:
                return findings

            check_id = check.get("check_id", "unknown")
            resource = check.get("resource", "")

            # Normalise file path
            file_path = check.get("repo_file_path") or check.get("file_path", "")
            try:
                file_path = str(Path(file_path).relative_to(repo_path))
            except (ValueError, TypeError):
                file_path = file_path.lstrip("/\\")

            line_range = check.get("file_line_range", [None])
            line = line_range[0] if line_range else None

            # check name can be a string or dict
            check_name = check.get("check", {})
            if isinstance(check_name, dict):
                check_name = check_name.get("name", "Security check failed")
            check_name = str(check_name)[:120]

            guideline = check.get("guideline", "")

            finding = Finding(
                title=f"Config: {check_id} — {check_name}",
                category=_categorize_check(check_id),
                severity=_infer_severity(check_id),
                confidence=Confidence.MEDIUM,
                file=file_path,
                line=line,
                description=(
                    f"Checkov check {check_id} failed for resource '{resource}'. "
                    f"{check_name}"
                ),
                evidence=(
                    f"Check ID: {check_id} | Resource: {resource} | File: {file_path}"
                ),
                recommendation=(
                    guideline
                    or f"Remediate {check_id} following Checkov documentation: "
                    f"https://www.checkov.io/5.Policy%20Index/terraform.html"
                ),
                source="Checkov",
                status=FindingStatus.MANUAL_REVIEW,
                rule_id=check_id,
            )
            findings.append(finding.to_dict())

    return findings


def _run_checkov(repo_path: str) -> List[Dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["checkov", "-d", repo_path, "--output", "json", "--quiet", "--compact"],
            capture_output=True,
            text=True,
            timeout=AGENT_TIMEOUT_SECONDS,
        )

        output = proc.stdout.strip()
        if not output:
            return []

        # Checkov may output multiple JSON objects; try the full string first
        try:
            raw = json.loads(output)
        except json.JSONDecodeError:
            # Try line-by-line
            for line in reversed(output.splitlines()):
                line = line.strip()
                if line.startswith(("{", "[")):
                    try:
                        raw = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                return []

        return _parse_checkov_output(raw, repo_path)

    except subprocess.TimeoutExpired:
        logger.error("Checkov timed out")
        return []
    except Exception as exc:
        logger.exception("Checkov error: %s", exc)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Custom Dockerfile rules (always run, supplement Checkov)
# ─────────────────────────────────────────────────────────────────────────────

_DOCKERFILE_RULES: List[Dict[str, Any]] = [
    {
        "id": "CUSTOM_DOCKER_001",
        "title": "Container May Run as Root (No USER Instruction)",
        "check": lambda lines: not any(l.strip().upper().startswith("USER ") for l in lines),
        "description": (
            "No USER instruction was found in the Dockerfile. The container "
            "may run as root by default, increasing the blast radius of a compromise."
        ),
        "recommendation": (
            "Add a USER instruction to run the container as a non-root user: "
            "USER appuser"
        ),
        "severity": Severity.HIGH,
        "category": "Container Security",
    },
    {
        "id": "CUSTOM_DOCKER_002",
        "title": "Base Image Uses 'latest' Tag",
        "check": lambda lines: any(
            l.strip().upper().startswith("FROM ") and ":latest" in l.lower()
            for l in lines
        ),
        "description": (
            "Using the 'latest' tag is non-deterministic. Future builds may "
            "pull a different image, introducing unexpected changes or vulnerabilities."
        ),
        "recommendation": (
            "Pin the base image to a specific version digest or semantic version tag."
        ),
        "severity": Severity.MEDIUM,
        "category": "Container Security",
    },
    {
        "id": "CUSTOM_DOCKER_003",
        "title": "ADD Used Instead of COPY",
        "check": lambda lines: any(l.strip().upper().startswith("ADD ") for l in lines),
        "description": (
            "ADD has implicit behaviours (URL fetching, auto-extraction) that "
            "can be surprising. COPY is safer for simple file copying."
        ),
        "recommendation": "Replace ADD with COPY for simple file-copy operations.",
        "severity": Severity.LOW,
        "category": "Container Security",
    },
    {
        "id": "CUSTOM_DOCKER_004",
        "title": "Secrets May Be Passed as Build ARGs",
        "check": lambda lines: any(
            "ARG" in l.upper() and any(
                kw in l.upper() for kw in ("SECRET", "PASSWORD", "KEY", "TOKEN")
            )
            for l in lines
        ),
        "description": (
            "Docker build ARGs are visible in the image layer history. "
            "Passing secrets via ARG may expose them."
        ),
        "recommendation": (
            "Use Docker BuildKit secrets (--secret flag) instead of ARG for "
            "sensitive values."
        ),
        "severity": Severity.HIGH,
        "category": "Container Security",
    },
]


def _run_custom_dockerfile_rules(repo_path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    skip = {".git", "node_modules", "__pycache__"}

    for dockerfile in Path(repo_path).rglob("Dockerfile*"):
        if any(s in dockerfile.parts for s in skip) or not dockerfile.is_file():
            continue
        try:
            lines = dockerfile.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue

        relative = str(dockerfile.relative_to(repo_path))

        for rule in _DOCKERFILE_RULES:
            if rule["check"](lines):
                findings.append(Finding(
                    title=rule["title"],
                    category=rule["category"],
                    severity=rule["severity"],
                    confidence=Confidence.MEDIUM,
                    file=relative,
                    description=rule["description"],
                    evidence=f"Dockerfile: {relative}",
                    recommendation=rule["recommendation"],
                    source="Custom Rules",
                    status=FindingStatus.MANUAL_REVIEW,
                    rule_id=rule["id"],
                ).to_dict())

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def run_config_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan infrastructure and configuration files for security issues.

    Runs Checkov (if available) plus custom Dockerfile rules.
    """
    findings: List[Dict[str, Any]] = []

    if _checkov_available():
        logger.info("Running Checkov on %s", repo_path)
        checkov_findings = _run_checkov(repo_path)
        findings.extend(checkov_findings)
        logger.info("Checkov: %d issues", len(checkov_findings))
    else:
        logger.warning("Checkov not found — skipping IaC scan.")

    custom_findings = _run_custom_dockerfile_rules(repo_path)
    findings.extend(custom_findings)
    logger.info("Custom rules: %d issues", len(custom_findings))

    return findings[:MAX_FINDINGS_PER_AGENT]
