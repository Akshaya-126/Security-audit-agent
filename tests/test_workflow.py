"""
Integration tests for the LangGraph workflow.

Uses mocked scanners and LLM calls so no real API keys or binary
tools are required to run these tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.graph.routing import route_to_agents
from src.graph.state import ScanState


class TestRouting:
    """Unit tests for the conditional routing function."""

    def test_github_only_routes_to_three_agents(self):
        state: ScanState = {
            "github_url": "https://github.com/owner/repo",
            "website_url": None,
        }
        agents = route_to_agents(state)
        assert "code_agent" in agents
        assert "dependency_agent" in agents
        assert "config_agent" in agents
        assert "website_agent" not in agents

    def test_website_only_routes_to_website_agent(self):
        state: ScanState = {
            "github_url": None,
            "website_url": "https://example.com",
        }
        agents = route_to_agents(state)
        assert "website_agent" in agents
        assert "code_agent" not in agents
        assert "dependency_agent" not in agents

    def test_both_targets_routes_to_all_agents(self):
        state: ScanState = {
            "github_url": "https://github.com/owner/repo",
            "website_url": "https://example.com",
        }
        agents = route_to_agents(state)
        assert "code_agent" in agents
        assert "dependency_agent" in agents
        assert "config_agent" in agents
        assert "website_agent" in agents

    def test_no_targets_routes_to_verification(self):
        state: ScanState = {"github_url": None, "website_url": None}
        agents = route_to_agents(state)
        assert agents == ["verification_agent"]

    def test_empty_state_routes_to_verification(self):
        state: ScanState = {}
        agents = route_to_agents(state)
        assert "verification_agent" in agents


class TestOrchestratorNode:
    """Unit tests for the orchestrator node."""

    @patch("src.agents.orchestrator.validate_github_url")
    @patch("src.agents.orchestrator.clone_repository")
    def test_valid_github_url_clones_repo(self, mock_clone, mock_validate):
        from src.agents.orchestrator import orchestrator_node

        mock_validate.return_value = (True, None, "owner", "repo")
        mock_clone.return_value = "/tmp/test_repo"

        state: ScanState = {
            "scan_id": "test-001",
            "github_url": "https://github.com/owner/repo",
            "website_url": None,
            "errors": [],
            "skipped_agents": [],
        }

        result = orchestrator_node(state)
        assert result["target_type"] == "github"
        assert result["repo_path"] == "/tmp/test_repo"
        assert result["errors"] == []

    @patch("src.agents.orchestrator.validate_github_url")
    def test_invalid_github_url_skips_agents(self, mock_validate):
        from src.agents.orchestrator import orchestrator_node

        mock_validate.return_value = (False, "Invalid URL format", None, None)

        state: ScanState = {
            "scan_id": "test-002",
            "github_url": "not-a-url",
            "website_url": None,
            "errors": [],
            "skipped_agents": [],
        }

        result = orchestrator_node(state)
        assert len(result["errors"]) > 0
        assert "code_agent" in result["skipped_agents"]

    @patch("src.agents.orchestrator.validate_website_url")
    def test_valid_website_url(self, mock_validate):
        from src.agents.orchestrator import orchestrator_node

        mock_validate.return_value = (True, None)

        state: ScanState = {
            "scan_id": "test-003",
            "github_url": None,
            "website_url": "https://example.com",
            "errors": [],
            "skipped_agents": [],
        }

        result = orchestrator_node(state)
        assert result["target_type"] == "website"
        assert result["repo_path"] is None


class TestVerificationAgent:
    """Unit tests for the verification and triage agent."""

    def _make_finding(self, **kwargs):
        defaults = {
            "id": "abc123",
            "title": "Test Finding",
            "category": "Injection",
            "severity": "high",
            "confidence": "medium",
            "file": "src/app.py",
            "line": 10,
            "description": "Test description",
            "evidence": "Test evidence",
            "recommendation": "Test recommendation",
            "source": "Semgrep",
            "status": "manual_review",
        }
        defaults.update(kwargs)
        return defaults

    def test_deduplication_removes_duplicate(self):
        from src.agents.verification_agent import verification_agent_node

        finding = self._make_finding()
        # Same file + line + title = duplicate
        finding2 = self._make_finding(title="Test Finding", id="xyz456")

        state: ScanState = {
            "code_findings": [finding, finding2],
            "dependency_findings": [],
            "website_findings": [],
            "config_findings": [],
            "repo_path": None,
            "errors": [],
            "skipped_agents": [],
        }

        result = verification_agent_node(state)
        verified = result["verified_findings"]
        assert len(verified) == 1  # duplicate removed

    def test_findings_sorted_by_severity(self):
        from src.agents.verification_agent import verification_agent_node

        findings = [
            self._make_finding(severity="low", id="1", line=1, title="A"),
            self._make_finding(severity="critical", id="2", line=2, title="B"),
            self._make_finding(severity="medium", id="3", line=3, title="C"),
        ]

        state: ScanState = {
            "code_findings": findings,
            "dependency_findings": [],
            "website_findings": [],
            "config_findings": [],
            "repo_path": None,
            "errors": [],
            "skipped_agents": [],
        }

        result = verification_agent_node(state)
        verified = result["verified_findings"]
        severities = [f["severity"] for f in verified]
        assert severities[0] == "critical"

    def test_osv_findings_marked_confirmed(self):
        from src.agents.verification_agent import verification_agent_node

        dep_finding = self._make_finding(
            source="OSV-Scanner",
            confidence="high",
            line=None,
            file="requirements.txt",
        )

        state: ScanState = {
            "code_findings": [],
            "dependency_findings": [dep_finding],
            "website_findings": [],
            "config_findings": [],
            "repo_path": None,
            "errors": [],
            "skipped_agents": [],
        }

        result = verification_agent_node(state)
        verified = result["verified_findings"]
        assert verified[0]["status"] == "confirmed"

    def test_empty_findings_returns_empty_verified(self):
        from src.agents.verification_agent import verification_agent_node

        state: ScanState = {
            "code_findings": [],
            "dependency_findings": [],
            "website_findings": [],
            "config_findings": [],
            "repo_path": None,
            "errors": [],
            "skipped_agents": [],
        }

        result = verification_agent_node(state)
        assert result["verified_findings"] == []


class TestScanCompletionStatus:
    """A scan with skipped checks must not be reported as fully complete."""

    @patch("api.get_workflow")
    def test_scan_with_errors_is_partial(self, mock_get_workflow):
        from api import _run_scan, _scans

        workflow = MagicMock()
        workflow.invoke.return_value = {
            "verified_findings": [],
            "errors": ["Clone failed: Repository is too large."],
            "skipped_agents": ["code_agent", "dependency_agent"],
            "agent_statuses": {},
        }
        mock_get_workflow.return_value = workflow
        _scans["test-partial"] = {"status": "running"}

        _run_scan("test-partial", "https://github.com/owner/repo", None)

        assert _scans["test-partial"]["status"] == "partial"
        assert _scans["test-partial"]["errors"]
        del _scans["test-partial"]


class TestIncompleteReportSummary:
    @patch("src.agents.report_agent.report_service.save_pdf_report", return_value=None)
    @patch("src.agents.report_agent.report_service.save_json_report", return_value=None)
    @patch("src.agents.report_agent.llm_service.summarize_findings")
    def test_empty_incomplete_scan_is_not_described_as_clean(
        self, mock_summary, _mock_json, _mock_pdf
    ):
        from src.agents.report_agent import report_agent_node

        result = report_agent_node({
            "scan_id": "test-incomplete",
            "github_url": "https://github.com/owner/large-repo",
            "verified_findings": [],
            "errors": ["Repository is too large."],
            "skipped_agents": ["code_agent"],
        })

        assert "incomplete" in result["report"]["executive_summary"].lower()
        assert "not a clean security result" in result["report"]["executive_summary"].lower()
        mock_summary.assert_not_called()
