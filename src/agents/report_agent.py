"""
Report Generation Agent — LangGraph node.

Uses Gemini API to:
  1. Enrich each finding with a plain-English explanation and remediation
  2. Generate an executive summary
  3. Assemble the structured report dict

Delegates PDF/JSON file generation to report_service.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from src.graph.state import ScanState
from src.schemas.findings import Severity
from src.services import llm_service, report_service

logger = logging.getLogger(__name__)


def _build_severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    breakdown: Dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.get("severity", Severity.INFO.value)
        breakdown[sev] = breakdown.get(sev, 0) + 1
    return breakdown


def _target_label(state: ScanState) -> str:
    parts = []
    if state.get("github_url"):
        parts.append(state["github_url"])
    if state.get("website_url"):
        parts.append(state["website_url"])
    return " | ".join(parts) or "Unknown target"


def report_agent_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: enrich findings with AI and generate report."""
    logger.info("Report agent: starting")

    verified = list(state.get("verified_findings") or [])
    target = _target_label(state)

    # ── AI enrichment (findings) ──────────────────────────────────────────────
    # Only enrich the top N to avoid excessive API calls
    max_enrich = int(os.environ.get("MAX_ENRICHED_FINDINGS", "30"))
    enriched_count = 0

    for finding in verified:
        if enriched_count >= max_enrich:
            break
        try:
            finding["ai_explanation"] = llm_service.explain_finding(finding)
            finding["ai_remediation"] = llm_service.suggest_remediation(finding)
            enriched_count += 1
        except Exception as exc:
            logger.warning("LLM enrichment failed for finding '%s': %s", finding.get("title"), exc)

    logger.info("Report agent: enriched %d/%d findings", enriched_count, len(verified))

    # ── Executive summary ─────────────────────────────────────────────────────
    errors = list(state.get("errors") or [])
    skipped_agents = list(state.get("skipped_agents") or [])
    scan_incomplete = bool(errors or skipped_agents)

    if scan_incomplete and not verified:
        exec_summary = (
            f"The scan of '{target}' was incomplete and returned no findings from "
            "the checks that ran. This is not a clean security result. Review the "
            "scan issues and rerun after resolving them."
        )
    else:
        try:
            exec_summary = llm_service.summarize_findings(verified, target)
        except Exception as exc:
            logger.warning("Failed to generate executive summary: %s", exc)
            exec_summary = (
                f"Security scan of '{target}' identified {len(verified)} findings."
            )
        if scan_incomplete:
            exec_summary = (
                "This scan was incomplete; some checks were skipped or reported "
                "errors. Do not treat it as a clean result. " + exec_summary
            )

    # ── Assemble report dict ──────────────────────────────────────────────────
    report: Dict[str, Any] = {
        "scan_id": state.get("scan_id", "unknown"),
        "target": target,
        "github_url": state.get("github_url"),
        "website_url": state.get("website_url"),
        "target_type": state.get("target_type", "unknown"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "executive_summary": exec_summary,
        "findings_count": len(verified),
        "severity_breakdown": _build_severity_breakdown(verified),
        "agent_statuses": state.get("agent_statuses", {}),
        "skipped_agents": skipped_agents,
        "errors": errors,
        "findings": verified,
    }

    # ── Save reports ──────────────────────────────────────────────────────────
    scan_id = state.get("scan_id", "unknown")
    reports_dir = os.environ.get("REPORTS_DIR", "reports")

    json_path: str | None = None
    pdf_path: str | None = None

    try:
        json_path = report_service.save_json_report(report, scan_id, reports_dir)
        logger.info("JSON report saved: %s", json_path)
    except Exception as exc:
        logger.error("Failed to save JSON report: %s", exc)

    try:
        pdf_path = report_service.save_pdf_report(report, scan_id, reports_dir)
        logger.info("PDF report saved: %s", pdf_path)
    except Exception as exc:
        logger.error("Failed to save PDF report: %s", exc)

    return {
        "report": report,
        "report_json_path": json_path,
        "report_pdf_path": pdf_path,
        "verified_findings": verified,
        "status": "completed",
        "errors": [],
        "skipped_agents": [],
    }
