"""
Website Security Agent — LangGraph node.

Runs the passive HTTPX-based website scanner.
Returns findings in state.website_findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from src.graph.state import ScanState
from src.scanners.website_scanner import run_website_scan

logger = logging.getLogger(__name__)


def website_agent_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: run website security scan."""
    website_url = state.get("website_url")

    if not website_url:
        logger.warning("Website agent: no website_url — skipping.")
        return {
            "website_findings": [],
            "skipped_agents": ["website_agent"],
            "agent_statuses": {"website_agent": "skipped"},
            "errors": [],
        }

    logger.info("Website agent: scanning %s", website_url)
    errors: list[str] = []

    try:
        findings = run_website_scan(website_url)
        logger.info("Website agent: %d issues found", len(findings))
    except Exception as exc:
        msg = f"Website scanner error: {exc}"
        logger.exception(msg)
        findings = []
        errors.append(msg)

    return {
        "website_findings": findings,
        "errors": errors,
        "agent_statuses": {"website_agent": "done"},
        "skipped_agents": [],
    }
