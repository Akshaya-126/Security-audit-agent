"""
Configuration Analysis Agent — LangGraph node.

Runs Checkov + custom Dockerfile rules on the cloned repository.
Returns findings in state.config_findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from src.graph.state import ScanState
from src.scanners.config_scanner import run_config_scan

logger = logging.getLogger(__name__)


def config_agent_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: run infrastructure / configuration security scan."""
    repo_path = state.get("repo_path")

    if not repo_path:
        logger.warning("Config agent: no repo_path — skipping.")
        return {
            "config_findings": [],
            "skipped_agents": ["config_agent"],
            "agent_statuses": {"config_agent": "skipped"},
            "errors": [],
        }

    logger.info("Config agent: scanning %s", repo_path)
    errors: list[str] = []

    try:
        findings = run_config_scan(repo_path)
        logger.info("Config agent: %d issues found", len(findings))
    except Exception as exc:
        msg = f"Config scanner error: {exc}"
        logger.exception(msg)
        findings = []
        errors.append(msg)

    return {
        "config_findings": findings,
        "errors": errors,
        "agent_statuses": {"config_agent": "done"},
        "skipped_agents": [],
    }
