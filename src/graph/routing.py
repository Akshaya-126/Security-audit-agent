"""
LangGraph conditional routing functions.

These functions are used as the routing logic for `add_conditional_edges`
in the workflow graph.  They return a list of node names to execute next,
enabling parallel fan-out to applicable scanning agents.
"""

from __future__ import annotations

from typing import List

from src.graph.state import ScanState


def route_to_agents(state: ScanState) -> List[str]:
    """
    Determine which scanning agents should run based on the submitted targets.

    Returns a list of node names.  LangGraph will execute all returned nodes
    concurrently (parallel fan-out), then wait for all to complete before
    proceeding to the verification node.

    If neither a GitHub URL nor a website URL is set, route directly to
    verification (which will produce an empty report).
    """
    agents: List[str] = []

    if state.get("github_url"):
        agents.extend(["code_agent", "dependency_agent", "config_agent"])

    if state.get("website_url"):
        agents.append("website_agent")

    if not agents:
        # Nothing to scan — go straight to verification
        return ["verification_agent"]

    return agents


def route_after_verification(state: ScanState) -> str:
    """Route from verification to the report node (always)."""
    return "report_agent"
