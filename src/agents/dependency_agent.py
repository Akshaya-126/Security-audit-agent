"""
Dependency Analysis Agent — LangGraph node.

Runs OSV-Scanner (or fallback OSV API) on the cloned repository.
Returns findings in state.dependency_findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from src.graph.state import ScanState
from src.scanners.dependency_scanner import run_dependency_scan

logger = logging.getLogger(__name__)


def dependency_agent_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: run dependency vulnerability scan."""
    repo_path = state.get("repo_path")

    if not repo_path:
        logger.warning("Dependency agent: no repo_path — skipping.")
        return {
            "dependency_findings": [],
            "skipped_agents": ["dependency_agent"],
            "agent_statuses": {"dependency_agent": "skipped"},
            "errors": [],
        }

    logger.info("Dependency agent: scanning %s", repo_path)
    errors: list[str] = []

    try:
        findings = run_dependency_scan(repo_path)
        logger.info("Dependency agent: %d vulnerabilities found", len(findings))
    except Exception as exc:
        msg = f"Dependency scanner error: {exc}"
        logger.exception(msg)
        findings = []
        errors.append(msg)

    return {
        "dependency_findings": findings,
        "errors": errors,
        "agent_statuses": {"dependency_agent": "done"},
        "skipped_agents": [],
    }
