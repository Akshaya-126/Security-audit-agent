"""
Code Analysis Agent — LangGraph node.

Runs Semgrep (static code analysis) and Gitleaks / regex secret scanner
on the cloned repository.  Returns combined findings in state.code_findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from src.graph.state import ScanState
from src.scanners.secret_scanner import run_secret_scan
from src.scanners.semgrep_scanner import run_semgrep_scan

logger = logging.getLogger(__name__)


def code_agent_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: run Semgrep + secret scanner on the repo."""
    repo_path = state.get("repo_path")

    if not repo_path:
        logger.warning("Code agent: no repo_path in state — skipping.")
        return {
            "code_findings": [],
            "skipped_agents": ["code_agent"],
            "agent_statuses": {"code_agent": "skipped"},
            "errors": [],
        }

    logger.info("Code agent: scanning %s", repo_path)

    findings = []
    errors: list[str] = []

    # ── Semgrep ───────────────────────────────────────────────────────────────
    try:
        semgrep_findings = run_semgrep_scan(repo_path)
        findings.extend(semgrep_findings)
        logger.info("Semgrep: %d findings", len(semgrep_findings))
    except Exception as exc:
        msg = f"Semgrep scanner error: {exc}"
        logger.exception(msg)
        errors.append(msg)

    # ── Secret scanner ────────────────────────────────────────────────────────
    try:
        secret_findings = run_secret_scan(repo_path)
        findings.extend(secret_findings)
        logger.info("Secret scanner: %d findings", len(secret_findings))
    except Exception as exc:
        msg = f"Secret scanner error: {exc}"
        logger.exception(msg)
        errors.append(msg)

    logger.info("Code agent: total %d findings", len(findings))

    return {
        "code_findings": findings,
        "errors": errors,
        "agent_statuses": {"code_agent": "done"},
        "skipped_agents": [],
    }
