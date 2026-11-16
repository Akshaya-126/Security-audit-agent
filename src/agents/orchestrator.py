"""
Orchestrator Agent — LangGraph node.

The first node in the workflow.  It:
  1. Validates the submitted URLs
  2. Determines the target type ("github" | "website" | "both")
  3. Clones the GitHub repository to a temporary directory (if applicable)
  4. Initialises workflow metadata fields
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict

from src.graph.state import ScanState
from src.security.url_validator import validate_github_url, validate_website_url
from src.services.github_service import GitHubServiceError, clone_repository

logger = logging.getLogger(__name__)


def orchestrator_node(state: ScanState) -> Dict[str, Any]:
    """LangGraph node: validate inputs, classify target, clone repo."""
    logger.info("Orchestrator: scan_id=%s", state.get("scan_id"))

    errors: list[str] = []
    skipped: list[str] = []
    agent_statuses: Dict[str, str] = {}

    github_url = state.get("github_url")
    website_url = state.get("website_url")
    repo_path: str | None = None

    # ── Validate GitHub URL ───────────────────────────────────────────────────
    validated_github: str | None = None
    if github_url:
        ok, err, owner, repo = validate_github_url(github_url)
        if not ok:
            errors.append(f"Invalid GitHub URL: {err}")
            skipped.extend(["code_agent", "dependency_agent", "config_agent"])
            for a in ("code_agent", "dependency_agent", "config_agent"):
                agent_statuses[a] = "skipped"
        else:
            validated_github = github_url
            # Clone the repository
            try:
                repo_path = clone_repository(github_url)
                logger.info("Repository cloned to %s", repo_path)
                for a in ("code_agent", "dependency_agent", "config_agent"):
                    agent_statuses[a] = "pending"
            except GitHubServiceError as exc:
                errors.append(f"Clone failed: {exc}")
                skipped.extend(["code_agent", "dependency_agent", "config_agent"])
                for a in ("code_agent", "dependency_agent", "config_agent"):
                    agent_statuses[a] = "skipped"
                validated_github = None

    # ── Validate website URL ──────────────────────────────────────────────────
    validated_website: str | None = None
    if website_url:
        ok, err = validate_website_url(website_url)
        if not ok:
            errors.append(f"Invalid website URL: {err}")
            skipped.append("website_agent")
            agent_statuses["website_agent"] = "skipped"
        else:
            validated_website = website_url
            agent_statuses["website_agent"] = "pending"

    # ── Determine target type ─────────────────────────────────────────────────
    if validated_github and validated_website:
        target_type = "both"
    elif validated_github:
        target_type = "github"
    elif validated_website:
        target_type = "website"
    else:
        target_type = "none"

    return {
        "github_url": validated_github,
        "website_url": validated_website,
        "target_type": target_type,
        "repo_path": repo_path,
        "status": "running",
        "errors": errors,
        "skipped_agents": skipped,
        "agent_statuses": agent_statuses,
        # Initialise finding lists so downstream nodes can safely extend them
        "code_findings": [],
        "dependency_findings": [],
        "website_findings": [],
        "config_findings": [],
        "verified_findings": [],
    }
