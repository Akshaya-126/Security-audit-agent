"""
Verification and Triage Agent — LangGraph node.

Consolidates findings from all scanning agents, deduplicates them,
normalises severity / confidence, and categorises each finding as:
  - confirmed   : high-confidence, strong scanner evidence
  - likely      : medium-confidence, plausible but not certain
  - manual_review : low-confidence or ambiguous
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from src.graph.state import ScanState
from src.schemas.findings import Confidence, FindingStatus, Severity

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Deduplication fingerprint
# ─────────────────────────────────────────────────────────────────────────────

def _fingerprint(finding: Dict[str, Any]) -> Tuple:
    """Return a hashable fingerprint used to detect duplicate findings."""
    return (
        (finding.get("file") or "").lower(),
        finding.get("line") or 0,
        (finding.get("rule_id") or finding.get("title") or "").lower()[:60],
        (finding.get("category") or "").lower(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Status classification rules
# ─────────────────────────────────────────────────────────────────────────────

def _classify_status(finding: Dict[str, Any]) -> FindingStatus:
    """
    Assign a verification status based on confidence and source.

    Rules (in order):
    1. If confidence is HIGH  → confirmed
    2. If confidence is MEDIUM and severity is HIGH/CRITICAL → likely
    3. Otherwise → manual_review

    Some sources (OSV, HTTPX, Gitleaks) have inherently high confidence.
    """
    source = (finding.get("source") or "").lower()
    confidence = (finding.get("confidence") or "").lower()
    severity = (finding.get("severity") or "").lower()

    # Sources with deterministic, evidence-backed output
    high_confidence_sources = {"osv-scanner", "osv api", "httpx", "tls check", "gitleaks"}
    if source in high_confidence_sources or confidence == "high":
        return FindingStatus.CONFIRMED

    if confidence == "medium" and severity in ("critical", "high"):
        return FindingStatus.LIKELY

    return FindingStatus.MANUAL_REVIEW


def _merge_agent_statuses(state: ScanState) -> Dict[str, str]:
    """Merge agent_statuses written by parallel nodes."""
    merged: Dict[str, str] = dict(state.get("agent_statuses") or {})
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# Node
# ─────────────────────────────────────────────────────────────────────────────

def verification_agent_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: consolidate, deduplicate, and classify findings."""
    logger.info("Verification agent: starting consolidation")

    # ── Collect all findings from all scanning agents ─────────────────────────
    all_findings: List[Dict[str, Any]] = []
    all_findings.extend(state.get("code_findings") or [])
    all_findings.extend(state.get("dependency_findings") or [])
    all_findings.extend(state.get("website_findings") or [])
    all_findings.extend(state.get("config_findings") or [])

    logger.info("Verification agent: %d total raw findings", len(all_findings))

    # ── Deduplication ─────────────────────────────────────────────────────────
    seen: dict[Tuple, Dict[str, Any]] = {}
    for f in all_findings:
        fp = _fingerprint(f)
        if fp not in seen:
            seen[fp] = f
        else:
            # Keep the finding from the higher-confidence source
            existing_conf = (seen[fp].get("confidence") or "low").lower()
            new_conf = (f.get("confidence") or "low").lower()
            conf_rank = {"high": 2, "medium": 1, "low": 0}
            if conf_rank.get(new_conf, 0) > conf_rank.get(existing_conf, 0):
                seen[fp] = f

    deduplicated = list(seen.values())
    logger.info(
        "Verification agent: %d findings after deduplication (%d removed)",
        len(deduplicated),
        len(all_findings) - len(deduplicated),
    )

    # ── Classification ────────────────────────────────────────────────────────
    for f in deduplicated:
        f["status"] = _classify_status(f).value

    # ── Severity normalisation ─────────────────────────────────────────────────
    valid_severities = {s.value for s in Severity}
    for f in deduplicated:
        if f.get("severity") not in valid_severities:
            f["severity"] = Severity.MEDIUM.value

    # ── Sort: critical → high → medium → low → info ───────────────────────────
    _sev_order = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 3,
        Severity.INFO.value: 4,
    }
    deduplicated.sort(key=lambda f: _sev_order.get(f.get("severity", "info"), 5))

    # ── Cleanup: remove temp repo ─────────────────────────────────────────────
    repo_path = state.get("repo_path")
    if repo_path:
        from src.services.github_service import cleanup_repository
        try:
            cleanup_repository(repo_path)
        except Exception as exc:
            logger.warning("Could not clean up repo: %s", exc)

    return {
        "verified_findings": deduplicated,
        "status": "verified",
        "errors": [],
        "skipped_agents": [],
    }
