"""
LangGraph workflow definition.

Assembles the StateGraph that orchestrates all six agents:

  START
    └─ orchestrator_node
         └─ [conditional fan-out — parallel]
               ├─ code_agent_node       (if github_url)
               ├─ dependency_agent_node (if github_url)
               ├─ config_agent_node     (if github_url)
               └─ website_agent_node    (if website_url)
         └─ [fan-in — all complete]
               └─ verification_node
                     └─ report_node
                           └─ END
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from src.agents.code_agent import code_agent_node
from src.agents.config_agent import config_agent_node
from src.agents.dependency_agent import dependency_agent_node
from src.agents.orchestrator import orchestrator_node
from src.agents.report_agent import report_agent_node
from src.agents.verification_agent import verification_agent_node
from src.agents.website_agent import website_agent_node
from src.graph.routing import route_to_agents
from src.graph.state import ScanState

logger = logging.getLogger(__name__)


def build_workflow():
    """
    Construct and compile the LangGraph StateGraph.

    Returns a compiled graph ready to be invoked with an initial ScanState.
    """
    graph = StateGraph(ScanState)

    # ── Register nodes ────────────────────────────────────────────────────────
    graph.add_node("orchestrator", orchestrator_node)
    graph.add_node("code_agent", code_agent_node)
    graph.add_node("dependency_agent", dependency_agent_node)
    graph.add_node("config_agent", config_agent_node)
    graph.add_node("website_agent", website_agent_node)
    graph.add_node("verification_agent", verification_agent_node)
    graph.add_node("report_agent", report_agent_node)

    # ── Entry point ───────────────────────────────────────────────────────────
    graph.add_edge(START, "orchestrator")

    # ── Fan-out: orchestrator → applicable scanning agents (parallel) ─────────
    # When route_to_agents returns a list, LangGraph executes all named nodes
    # concurrently as a single super-step.
    graph.add_conditional_edges(
        "orchestrator",
        route_to_agents,
        [
            "code_agent",
            "dependency_agent",
            "config_agent",
            "website_agent",
            "verification_agent",  # direct route when no agents apply
        ],
    )

    # ── Fan-in: all agents → verification (LangGraph waits for all) ──────────
    for agent in ("code_agent", "dependency_agent", "config_agent", "website_agent"):
        graph.add_edge(agent, "verification_agent")

    # ── Sequential tail: verification → report → END ─────────────────────────
    graph.add_edge("verification_agent", "report_agent")
    graph.add_edge("report_agent", END)

    compiled = graph.compile()
    logger.info("LangGraph workflow compiled successfully.")
    return compiled


# Module-level compiled graph (singleton)
_compiled_graph = None


def get_workflow():
    """Return the compiled workflow graph (lazy singleton)."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_workflow()
    return _compiled_graph
