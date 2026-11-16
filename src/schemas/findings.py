"""
Pydantic models for security findings, scan state, and API contracts.

All agents produce Finding objects in a consistent format so that the
Verification Agent can process results from different scanners uniformly.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    MANUAL_REVIEW = "manual_review"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


# ─────────────────────────────────────────────────────────────────────────────
# Core Finding Model
# ─────────────────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    """
    A single security finding produced by any scanner agent.

    All scanner wrappers must return Finding objects (via .to_dict())
    so that the Verification and Report agents can process them uniformly.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    category: str
    severity: Severity
    confidence: Confidence

    # Location (optional — not applicable to website findings)
    file: Optional[str] = None
    line: Optional[int] = None

    # Core content
    description: str
    evidence: str
    recommendation: str
    source: str  # e.g. "Semgrep", "Gitleaks", "OSV-Scanner", "HTTPX", "Checkov"
    status: FindingStatus = FindingStatus.MANUAL_REVIEW

    # Dependency-specific fields
    cve_id: Optional[str] = None
    osv_id: Optional[str] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None

    # Rule metadata
    rule_id: Optional[str] = None

    # Website-specific
    url: Optional[str] = None

    # AI-enriched fields — populated by Report Agent
    ai_explanation: Optional[str] = None
    ai_remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict for LangGraph state storage."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Deserialize from a plain dict."""
        return cls(**data)


# ─────────────────────────────────────────────────────────────────────────────
# API Request / Response Models
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Incoming scan request submitted via POST /scan."""

    github_url: Optional[str] = None
    website_url: Optional[str] = None

    @field_validator("github_url", "website_url", mode="before")
    @classmethod
    def strip_and_none_empty(cls, v: Optional[str]) -> Optional[str]:
        if isinstance(v, str):
            v = v.strip()
            return v if v else None
        return v

    @model_validator(mode="after")
    def require_a_target(self) -> "ScanRequest":
        if not self.github_url and not self.website_url:
            raise ValueError("Provide at least one GitHub repository or website URL.")
        return self


class ScanResult(BaseModel):
    """Scan result returned by GET /scan/{scan_id}."""

    scan_id: str
    status: ScanStatus
    target_type: Optional[str] = None
    github_url: Optional[str] = None
    website_url: Optional[str] = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    findings_count: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    agent_statuses: Dict[str, str] = Field(default_factory=dict)
    skipped_agents: List[str] = Field(default_factory=list)

    verified_findings: List[Dict[str, Any]] = Field(default_factory=list)

    report_json_path: Optional[str] = None
    report_pdf_path: Optional[str] = None

    errors: List[str] = Field(default_factory=list)
