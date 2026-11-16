"""
LangGraph shared workflow state definition.

ScanState is the single source of truth passed between all graph nodes.
Fields annotated with Annotated[List, operator.add] use LangGraph's
reducer mechanism — when parallel nodes both write to such a field,
their lists are merged instead of one overwriting the other.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict


def _merge_agent_statuses(
    current: Optional[Dict[str, str]],
    new_value: Optional[Dict[str, str]],
) -> Dict[str, str]:
    """Combine per-agent status updates from parallel graph branches."""
    merged = dict(current or {})
    merged.update(new_value or {})
    return merged


class ScanState(TypedDict, total=False):
    """
    Shared state threaded through the entire LangGraph workflow.

    Layout
    ------
    Input fields      → set by the caller / orchestrator node
    Per-agent fields  → each scanning agent writes to its own dedicated key
    Reducer fields    → lists safely merged across parallel nodes
    Downstream fields → set sequentially by verification and report nodes
    """

    # ── Input ─────────────────────────────────────────────────────────────────
    scan_id: str
    github_url: Optional[str]
    website_url: Optional[str]

    # ── Classification (set by orchestrator) ──────────────────────────────────
    target_type: str          # "github" | "website" | "both"
    repo_path: Optional[str]  # local temp dir for the cloned repo

    # ── Per-agent findings (each agent writes to its own field → no conflicts) ─
    code_findings: List[Dict[str, Any]]
    dependency_findings: List[Dict[str, Any]]
    website_findings: List[Dict[str, Any]]
    config_findings: List[Dict[str, Any]]

    # ── Reducer fields (safe to write from parallel nodes) ────────────────────
    errors: Annotated[List[str], operator.add]
    skipped_agents: Annotated[List[str], operator.add]

    # ── Downstream outputs (sequential) ──────────────────────────────────────
    verified_findings: List[Dict[str, Any]]
    report: Optional[Dict[str, Any]]
    report_json_path: Optional[str]
    report_pdf_path: Optional[str]

    # ── Workflow metadata ─────────────────────────────────────────────────────
    status: str
    agent_statuses: Annotated[Dict[str, str], _merge_agent_statuses]
