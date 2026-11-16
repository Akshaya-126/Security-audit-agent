"""
FastAPI backend for the AI-Powered Security Audit System.

Endpoints:
  POST /scan               — start a new scan (returns scan_id immediately)
  GET  /scan/{scan_id}     — get current scan status and results
  GET  /scan/{scan_id}/report/json — download JSON report
  GET  /scan/{scan_id}/report/pdf  — download PDF report
  GET  /health             — health check
"""

from __future__ import annotations

import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, SecretStr

from src.graph.workflow import get_workflow
from src.schemas.findings import ScanRequest, ScanResult, ScanStatus
from src.services.llm_service import draft_code_fix
from src.services.remediation_service import (
    MAX_FIX_FILE_BYTES,
    RemediationError,
    create_fix_pull_request,
    fetch_file_for_draft,
)
from src.security.redaction import redact_string
from src.scanners.secret_scanner import has_secret_like_value

load_dotenv()

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO")),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CypherX Security Audit API",
    description="Multi-agent security auditing powered by LangGraph and Gemini",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store (replace with a database in production)
_scans: Dict[str, Dict[str, Any]] = {}
_fix_drafts: Dict[str, Dict[str, Any]] = {}

# Thread pool for running LangGraph synchronously in background
_executor = ThreadPoolExecutor(max_workers=5)


class FixDraftRequest(BaseModel):
    """Request an AI-generated preview for an eligible code finding."""

    github_token: SecretStr = Field(min_length=20, max_length=500)
    consent_to_ai: bool


class CreatePullRequestRequest(BaseModel):
    """Approve a previously previewed fix and open a pull request."""

    github_token: SecretStr = Field(min_length=20, max_length=500)
    approved: bool


# ─────────────────────────────────────────────────────────────────────────────
# Background scan runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(scan_id: str, github_url: Optional[str], website_url: Optional[str]) -> None:
    """Run the LangGraph workflow synchronously in a background thread."""
    try:
        workflow = get_workflow()
        initial_state = {
            "scan_id": scan_id,
            "github_url": github_url,
            "website_url": website_url,
            "errors": [],
            "skipped_agents": [],
        }

        logger.info("Starting scan %s", scan_id)
        final_state = workflow.invoke(initial_state)

        verified = final_state.get("verified_findings", [])
        breakdown: Dict[str, int] = {}
        for f in verified:
            sev = f.get("severity", "info")
            breakdown[sev] = breakdown.get(sev, 0) + 1

        scan_status = (
            ScanStatus.PARTIAL.value
            if final_state.get("errors") or final_state.get("skipped_agents")
            else ScanStatus.COMPLETED.value
        )
        _scans[scan_id].update({
            "status": scan_status,
            "completed_at": datetime.utcnow().isoformat(),
            "findings_count": len(verified),
            "severity_breakdown": breakdown,
            "agent_statuses": final_state.get("agent_statuses", {}),
            "skipped_agents": list(final_state.get("skipped_agents") or []),
            "verified_findings": verified,
            "report_json_path": final_state.get("report_json_path"),
            "report_pdf_path": final_state.get("report_pdf_path"),
            "errors": list(final_state.get("errors") or []),
        })
        logger.info("Scan %s completed: %d findings", scan_id, len(verified))

    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        _scans[scan_id].update({
            "status": ScanStatus.FAILED.value,
            "completed_at": datetime.utcnow().isoformat(),
            "errors": [str(exc)],
        })


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/scan", response_model=Dict[str, str], status_code=202)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a security scan.

    Accepts a GitHub URL, a website URL, or both.
    Returns a scan_id immediately; poll GET /scan/{scan_id} for results.
    """
    if not request.github_url and not request.website_url:
        raise HTTPException(
            status_code=422,
            detail="At least one of 'github_url' or 'website_url' must be provided.",
        )

    scan_id = str(uuid.uuid4())[:12]
    _scans[scan_id] = {
        "scan_id": scan_id,
        "status": ScanStatus.RUNNING.value,
        "github_url": request.github_url,
        "website_url": request.website_url,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "findings_count": 0,
        "severity_breakdown": {},
        "agent_statuses": {},
        "skipped_agents": [],
        "verified_findings": [],
        "report_json_path": None,
        "report_pdf_path": None,
        "errors": [],
    }

    # Run in background thread
    _executor.submit(_run_scan, scan_id, request.github_url, request.website_url)

    return {"scan_id": scan_id, "status": "running"}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Get the current status and results of a scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return _scans[scan_id]


def _get_fixable_finding(scan_id: str, finding_id: str) -> Dict[str, Any]:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.get("status") not in {ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value}:
        raise HTTPException(status_code=409, detail="The scan has not completed.")
    if not scan.get("github_url"):
        raise HTTPException(status_code=422, detail="This scan has no GitHub repository.")

    finding = next(
        (
            item for item in scan.get("verified_findings", [])
            if str(item.get("id")) == finding_id
        ),
        None,
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found in this scan.")

    title = str(finding.get("title") or "").lower()
    category = str(finding.get("category") or "").lower()
    same_file_secret = any(
        str(item.get("file") or "") == str(finding.get("file") or "")
        and (
            str(item.get("category") or "").lower() == "secrets"
            or any(
                word in str(item.get("title") or "").lower()
                for word in ("secret", "password", "token", "credential", "api key")
            )
        )
        for item in scan.get("verified_findings", [])
    )
    if (
        not finding.get("file")
        or category == "secrets"
        or same_file_secret
        or any(word in title for word in ("secret", "password", "token", "credential", "api key"))
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "This finding or its file needs manual handling. Secret findings require "
                "credential rotation and are not eligible for an AI-generated code change."
            ),
        )
    return finding


@app.post("/scan/{scan_id}/findings/{finding_id}/fix-draft")
def create_fix_draft(
    scan_id: str,
    finding_id: str,
    request: FixDraftRequest,
):
    """Prepare a code diff for explicit review; never writes to GitHub."""
    if not request.consent_to_ai:
        raise HTTPException(
            status_code=422,
            detail="Consent is required before sending repository source to the configured AI service.",
        )
    finding = _get_fixable_finding(scan_id, finding_id)
    scan = _scans[scan_id]
    token = request.github_token.get_secret_value()

    try:
        repository = fetch_file_for_draft(
            scan["github_url"],
            str(finding["file"]),
            token,
        )
        updated_content = draft_code_fix(finding, repository["source"])
    except RemediationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if len(updated_content.encode("utf-8")) > MAX_FIX_FILE_BYTES:
        raise HTTPException(
            status_code=422,
            detail="The generated draft is too large to review or submit.",
        )
    if (
        redact_string(updated_content) != updated_content
        or has_secret_like_value(updated_content)
    ):
        raise HTTPException(
            status_code=422,
            detail="The generated draft appears to contain a secret and was rejected.",
        )

    now = datetime.now(timezone.utc)
    for draft_id, draft in list(_fix_drafts.items()):
        if draft["expires_at"] <= now:
            del _fix_drafts[draft_id]
    if len(_fix_drafts) >= 100:
        oldest = min(_fix_drafts, key=lambda key: _fix_drafts[key]["created_at"])
        del _fix_drafts[oldest]

    draft_id = uuid.uuid4().hex
    _fix_drafts[draft_id] = {
        "scan_id": scan_id,
        "finding_id": finding_id,
        "finding": finding,
        "repository": repository,
        "updated_content": updated_content,
        "created_at": now,
        "expires_at": now + timedelta(minutes=15),
    }
    return {
        "draft_id": draft_id,
        "file": repository["file_path"],
        "default_branch": repository["default_branch"],
        "original_content": repository["source"],
        "updated_content": updated_content,
        "expires_in_minutes": 15,
    }


@app.post("/scan/{scan_id}/findings/{finding_id}/pull-request")
def open_fix_pull_request(
    scan_id: str,
    finding_id: str,
    draft_id: str,
    request: CreatePullRequestRequest,
):
    """Create a branch and pull request only after explicit user approval."""
    if not request.approved:
        raise HTTPException(
            status_code=422,
            detail="Review the proposed diff and explicitly approve creating the pull request.",
        )
    draft = _fix_drafts.get(draft_id)
    if (
        not draft
        or draft["expires_at"] <= datetime.now(timezone.utc)
        or draft["scan_id"] != scan_id
        or draft["finding_id"] != finding_id
    ):
        _fix_drafts.pop(draft_id, None)
        raise HTTPException(
            status_code=404,
            detail="The preview is missing or expired. Generate a fresh fix preview.",
        )

    token = request.github_token.get_secret_value()
    try:
        result = create_fix_pull_request(
            draft["repository"],
            draft["updated_content"],
            draft["finding"],
            token,
        )
    except RemediationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    del _fix_drafts[draft_id]
    return result


@app.get("/scan/{scan_id}/report/json")
def download_json_report(scan_id: str):
    """Download the JSON report for a completed scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found.")

    scan = _scans[scan_id]
    if scan["status"] != ScanStatus.COMPLETED.value:
        raise HTTPException(status_code=409, detail="Scan has not completed yet.")

    json_path = scan.get("report_json_path")
    if not json_path or not Path(json_path).exists():
        raise HTTPException(status_code=404, detail="JSON report file not found.")

    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename=f"security-report-{scan_id}.json",
    )


@app.get("/scan/{scan_id}/report/pdf")
def download_pdf_report(scan_id: str):
    """Download the PDF report for a completed scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found.")

    scan = _scans[scan_id]
    if scan["status"] != ScanStatus.COMPLETED.value:
        raise HTTPException(status_code=409, detail="Scan has not completed yet.")

    pdf_path = scan.get("report_pdf_path")
    if not pdf_path or not Path(pdf_path).exists():
        raise HTTPException(status_code=404, detail="PDF report not found (ReportLab may not be installed).")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"security-report-{scan_id}.pdf",
    )


@app.get("/scans")
def list_scans():
    """List all scans (summary view)."""
    return [
        {
            "scan_id": s["scan_id"],
            "status": s["status"],
            "created_at": s.get("created_at"),
            "findings_count": s.get("findings_count", 0),
            "github_url": s.get("github_url"),
            "website_url": s.get("website_url"),
        }
        for s in reversed(list(_scans.values()))
    ]
