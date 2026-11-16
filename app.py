"""
Streamlit dashboard for CypherX.

Provides a security dashboard for submitting scans, monitoring progress,
and reviewing findings with clear explanations and remediation guidance.
"""

from __future__ import annotations

import difflib
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from src.security.scan_limits import (
    AGENT_TIMEOUT_SECONDS,
    GIT_CLONE_TIMEOUT_SECONDS,
    HTTP_REQUEST_TIMEOUT,
    MAX_FINDINGS_PER_AGENT,
    MAX_REPO_SIZE_BYTES,
)

API_BASE = os.environ.get("API_BASE_URL", "http://localhost:8000")

# ─────────────────────────────────────────────────────────────────────────────
# Page config (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CypherX | Security findings",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────────────────────
# Custom CSS — premium dark theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ─────────────────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: linear-gradient(135deg, #0A0F1E 0%, #0D1B2A 50%, #0A0F1E 100%);
    min-height: 100vh;
}

/* ── Header ─────────────────────────────────────────────────────────────── */
.hero-header {
    background: linear-gradient(135deg, rgba(99,102,241,0.15) 0%, rgba(168,85,247,0.1) 50%, rgba(59,130,246,0.15) 100%);
    border: 1px solid rgba(99,102,241,0.3);
    border-radius: 20px;
    padding: 2.5rem 3rem;
    margin-bottom: 2rem;
    backdrop-filter: blur(20px);
    position: relative;
    overflow: hidden;
}
.hero-header::before {
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: radial-gradient(circle at 30% 50%, rgba(99,102,241,0.08) 0%, transparent 60%);
    pointer-events: none;
}
.hero-title {
    font-size: 2.4rem;
    font-weight: 700;
    background: linear-gradient(135deg, #818CF8, #C084FC, #60A5FA);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin: 0 0 0.5rem 0;
    line-height: 1.2;
}
.hero-subtitle {
    font-size: 1rem;
    color: #94A3B8;
    margin: 0;
    font-weight: 400;
}
.hero-badges {
    display: flex;
    gap: 0.75rem;
    margin-top: 1.2rem;
    flex-wrap: wrap;
}
.tech-badge {
    background: rgba(99,102,241,0.15);
    border: 1px solid rgba(99,102,241,0.3);
    color: #A5B4FC;
    padding: 0.25rem 0.75rem;
    border-radius: 100px;
    font-size: 0.75rem;
    font-weight: 500;
}

/* ── Cards ──────────────────────────────────────────────────────────────── */
.glass-card {
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: 16px;
    padding: 1.5rem;
    backdrop-filter: blur(20px);
    margin-bottom: 1rem;
}

/* ── Severity badges ─────────────────────────────────────────────────────── */
.badge-critical { background: rgba(220,38,38,0.2); color:#FCA5A5; border:1px solid rgba(220,38,38,0.4); padding:2px 10px; border-radius:100px; font-size:0.72rem; font-weight:600; }
.badge-high     { background: rgba(234,88,12,0.2);  color:#FDBA74; border:1px solid rgba(234,88,12,0.4);  padding:2px 10px; border-radius:100px; font-size:0.72rem; font-weight:600; }
.badge-medium   { background: rgba(217,119,6,0.2);  color:#FCD34D; border:1px solid rgba(217,119,6,0.4);  padding:2px 10px; border-radius:100px; font-size:0.72rem; font-weight:600; }
.badge-low      { background: rgba(37,99,235,0.2);  color:#93C5FD; border:1px solid rgba(37,99,235,0.4);  padding:2px 10px; border-radius:100px; font-size:0.72rem; font-weight:600; }
.badge-info     { background: rgba(107,114,128,0.2);color:#D1D5DB; border:1px solid rgba(107,114,128,0.4);padding:2px 10px; border-radius:100px; font-size:0.72rem; font-weight:600; }

/* ── Status badges ───────────────────────────────────────────────────────── */
.status-confirmed    { background:rgba(21,128,61,0.2);  color:#86EFAC; border:1px solid rgba(21,128,61,0.4);   padding:2px 8px; border-radius:100px; font-size:0.7rem; }
.status-likely       { background:rgba(180,83,9,0.2);   color:#FDE68A; border:1px solid rgba(180,83,9,0.4);    padding:2px 8px; border-radius:100px; font-size:0.7rem; }
.status-manual_review{ background:rgba(107,114,128,0.2);color:#D1D5DB; border:1px solid rgba(107,114,128,0.4); padding:2px 8px; border-radius:100px; font-size:0.7rem; }

/* ── Finding card ────────────────────────────────────────────────────────── */
.finding-card {
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid rgba(99,102,241,0.15);
    border-radius: 12px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 0.75rem;
    transition: border-color 0.2s;
}
.finding-card:hover { border-color: rgba(99,102,241,0.4); }
.finding-title { font-size: 0.95rem; font-weight: 600; color: #E2E8F0; margin-bottom: 0.5rem; }
.finding-meta  { font-size: 0.8rem; color: #64748B; font-family: 'JetBrains Mono', monospace; margin-bottom: 0.5rem; }
.finding-desc  { font-size: 0.85rem; color: #94A3B8; line-height: 1.6; }

/* ── Agent status ────────────────────────────────────────────────────────── */
.agent-pill {
    display: inline-flex; align-items: center; gap: 0.4rem;
    padding: 0.4rem 0.9rem; border-radius: 100px;
    font-size: 0.8rem; font-weight: 500; margin: 0.2rem;
}
.agent-running  { background:rgba(99,102,241,0.2); color:#A5B4FC; border:1px solid rgba(99,102,241,0.3); }
.agent-done     { background:rgba(21,128,61,0.2);  color:#86EFAC; border:1px solid rgba(21,128,61,0.3);  }
.agent-skipped  { background:rgba(107,114,128,0.2);color:#9CA3AF; border:1px solid rgba(107,114,128,0.3);}
.agent-error    { background:rgba(220,38,38,0.2);  color:#FCA5A5; border:1px solid rgba(220,38,38,0.3);  }
.agent-pending  { background:rgba(217,119,6,0.2);  color:#FCD34D; border:1px solid rgba(217,119,6,0.3);  }

/* ── Metric tile ─────────────────────────────────────────────────────────── */
.metric-tile {
    background: rgba(15,23,42,0.9);
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: 12px;
    padding: 1.2rem;
    text-align: center;
}
.metric-value { font-size: 2rem; font-weight: 700; color: #E2E8F0; }
.metric-label { font-size: 0.8rem; color: #64748B; margin-top: 0.3rem; }

/* ── Scan button ─────────────────────────────────────────────────────────── */
div.stButton > button {
    background: linear-gradient(135deg, #6366F1, #8B5CF6) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 0.6rem 2rem !important;
    font-weight: 600 !important;
    font-size: 1rem !important;
    transition: all 0.2s !important;
    width: 100%;
}
div.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 8px 25px rgba(99,102,241,0.4) !important;
}

/* ── Input fields ────────────────────────────────────────────────────────── */
.stTextInput input {
    background: rgba(15,23,42,0.8) !important;
    border: 1px solid rgba(99,102,241,0.3) !important;
    border-radius: 10px !important;
    color: #E2E8F0 !important;
    font-size: 0.9rem !important;
}
.stTextInput input:focus {
    border-color: rgba(99,102,241,0.7) !important;
    box-shadow: 0 0 0 2px rgba(99,102,241,0.2) !important;
}

/* ── Tabs ────────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: rgba(15,23,42,0.5);
    border-radius: 10px;
    padding: 4px;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    color: #64748B !important;
    border-radius: 8px !important;
    font-weight: 500 !important;
}
.stTabs [aria-selected="true"] {
    background: rgba(99,102,241,0.3) !important;
    color: #A5B4FC !important;
}

/* ── Progress bar ────────────────────────────────────────────────────────── */
.stProgress > div > div { background: linear-gradient(90deg, #6366F1, #8B5CF6) !important; border-radius: 100px; }

/* ── Expander ────────────────────────────────────────────────────────────── */
.streamlit-expanderHeader {
    background: rgba(15,23,42,0.6) !important;
    border-radius: 8px !important;
    color: #94A3B8 !important;
}

/* ── Scrollbar ───────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0A0F1E; }
::-webkit-scrollbar-thumb { background: rgba(99,102,241,0.4); border-radius: 3px; }

/* Restrained workspace styling */
.stApp {
    background: #F4F7FB;
    color: #172033;
}
.main .block-container {
    max-width: 1440px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}
.hero-header {
    background: #111C34;
    border: 1px solid #263653;
    border-radius: 14px;
    padding: 2rem 2.25rem;
    box-shadow: 0 12px 30px rgba(15, 23, 42, 0.12);
}
.hero-header::before { display: none; }
.hero-title {
    color: #F8FAFC;
    background: none;
    -webkit-text-fill-color: #F8FAFC;
    font-size: 2rem;
}
.hero-subtitle { color: #CBD5E1; }
.tech-badge {
    background: #1D2B47;
    border-color: #344766;
    color: #D7E2F3;
}
.glass-card {
    background: #FFFFFF;
    border: 1px solid #DCE4EF;
    border-radius: 12px;
    box-shadow: 0 3px 12px rgba(15, 23, 42, 0.04);
    backdrop-filter: none;
}
.metric-tile {
    background: #FFFFFF;
    border: 1px solid #DCE4EF;
}
.metric-value { color: #172033; }
.metric-label { color: #64748B; }
.streamlit-expanderHeader {
    background: #FFFFFF !important;
    color: #263449 !important;
    border: 1px solid #DCE4EF !important;
}
.stTextInput input {
    background: #FFFFFF;
    color: #172033;
    border-color: #CBD5E1;
}
.stButton > button, .stLinkButton > a {
    border-radius: 8px;
    font-weight: 600;
}
.stButton > button[kind="primary"] {
    background: #3158C8;
    border-color: #3158C8;
}
.stProgress > div > div { background: #3158C8 !important; }
.hero-header {
    padding: 1.65rem 2rem;
    margin-bottom: 1rem;
    border-radius: 12px;
}
.hero-title { font-size: 1.9rem; }
.main .block-container { max-width: 1180px; }
.stMarkdown h2, .stMarkdown h3 { color: #172033; }
.stCaption, [data-testid="stCaptionContainer"] { color: #64748B; }
.finding-meta { color: #64748B; }
.finding-section {
    height: 100%;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 9px;
    padding: 0.85rem 1rem;
}
.finding-section h4 {
    margin: 0 0 0.55rem 0;
    color: #334155;
    font-size: 0.92rem;
}
.finding-section p {
    margin: 0;
    color: #334155;
    line-height: 1.65;
    white-space: pre-wrap;
}
.finding-evidence {
    border-left: 3px solid #94A3B8;
    padding: 0.55rem 0.8rem;
    margin-top: 0.75rem;
    background: #F8FAFC;
    color: #475569;
    border-radius: 0 6px 6px 0;
}
.badge-critical { background:#FEE2E2; color:#991B1B; border-color:#FECACA; }
.badge-high { background:#FFEDD5; color:#9A3412; border-color:#FED7AA; }
.badge-medium { background:#FEF3C7; color:#92400E; border-color:#FDE68A; }
.badge-low { background:#DBEAFE; color:#1E40AF; border-color:#BFDBFE; }
.badge-info { background:#E2E8F0; color:#334155; border-color:#CBD5E1; }
.status-confirmed { background:#DCFCE7; color:#166534; border-color:#BBF7D0; }
.status-likely { background:#FEF3C7; color:#92400E; border-color:#FDE68A; }
.status-manual_review { background:#E2E8F0; color:#334155; border-color:#CBD5E1; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# API helpers
# ─────────────────────────────────────────────────────────────────────────────

def api_start_scan(github_url: Optional[str], website_url: Optional[str]) -> Optional[str]:
    try:
        payload = {}
        if github_url:
            payload["github_url"] = github_url
        if website_url:
            payload["website_url"] = website_url
        resp = httpx.post(f"{API_BASE}/scan", json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json().get("scan_id")
    except httpx.HTTPError as exc:
        st.error(f"Could not start the scan: {exc}")
        return None


def api_get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    try:
        resp = httpx.get(f"{API_BASE}/scan/{scan_id}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc:
        st.error(f"Could not retrieve scan status: {exc}")
        return None


def _api_can_receive_github_token() -> bool:
    parsed = urlparse(API_BASE)
    return parsed.scheme == "https" or parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


def api_draft_fix(
    scan_id: str,
    finding_id: str,
    github_token: str,
) -> Optional[Dict[str, Any]]:
    if not _api_can_receive_github_token():
        st.error("A GitHub token can only be sent to a local or HTTPS API endpoint.")
        return None
    try:
        response = httpx.post(
            f"{API_BASE}/scan/{scan_id}/findings/{finding_id}/fix-draft",
            json={"github_token": github_token, "consent_to_ai": True},
            timeout=120,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", "The fix preview could not be generated.")
        except ValueError:
            detail = "The fix preview could not be generated."
        st.error(str(detail))
        return None
    except httpx.HTTPError as exc:
        st.error(f"Could not generate the fix preview: {exc}")
        return None


def api_create_fix_pr(
    scan_id: str,
    finding_id: str,
    draft_id: str,
    github_token: str,
) -> Optional[Dict[str, str]]:
    if not _api_can_receive_github_token():
        st.error("A GitHub token can only be sent to a local or HTTPS API endpoint.")
        return None
    try:
        response = httpx.post(
            f"{API_BASE}/scan/{scan_id}/findings/{finding_id}/pull-request",
            params={"draft_id": draft_id},
            json={"github_token": github_token, "approved": True},
            timeout=60,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail", "GitHub could not create the pull request.")
        except ValueError:
            detail = "GitHub could not create the pull request."
        st.error(str(detail))
        return None
    except httpx.HTTPError as exc:
        st.error(f"Could not create the pull request: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────────────────

def sev_badge(severity: str) -> str:
    s = severity.lower()
    if s not in {"critical", "high", "medium", "low", "info"}:
        s = "info"
    return f'<span class="badge-{s}">{s.upper()}</span>'


def _finding_explanation(finding: Dict[str, Any]) -> str:
    explanation = str(finding.get("ai_explanation") or "").strip()
    generic_prefix = "this is a "
    if explanation and not explanation.lower().startswith(generic_prefix):
        return explanation

    description = str(finding.get("description") or "").strip()
    title = str(finding.get("title") or "").lower()
    category = str(finding.get("category") or "").lower()
    if category == "secrets" or "password" in title or "secret" in title:
        if "password" in title:
            cause = (
                "A password-like value appears to be assigned directly in a source "
                "file. This often happens when a development credential or an "
                "environment-specific setting is committed with application code."
            )
        elif "token" in title or "api key" in title or "key" in title:
            cause = (
                "A credential-like value appears to be stored directly in a source "
                "file rather than supplied securely at runtime."
            )
        else:
            cause = (
                "A value in the source matches a pattern commonly used for a "
                "credential. The scanner hides the matched value."
            )
        impact = (
            "Anyone who can read the repository may be able to copy the value. "
            "If it is a real, active credential, it could allow access to the "
            "associated account or service."
        )
        verification = (
            "Check the indicated line without copying the value into logs or tickets. "
            "Confirm whether it is a real credential or a test placeholder; automated "
            "pattern matches can be false positives."
        )
        detail = f"{description} " if description else ""
        return f"{detail}{cause} {impact} {verification}"

    if category in {"vulnerable dependency", "dependency"} or finding.get("cve_id"):
        package = finding.get("package") or "the reported package"
        version = finding.get("installed_version") or "the installed version"
        fixed = finding.get("fixed_version")
        return (
            f"The dependency scanner identified {package} ({version}) as affected "
            "by a published security advisory. An affected version may contain a "
            "known weakness; actual exposure depends on how the application uses it. "
            f"{description} "
            + (
                f"Upgrade to {fixed}, or the nearest supported patched release, "
                "then run the dependency scan and your test suite again."
                if fixed
                else "Check the linked advisory for affected and patched versions, "
                "upgrade to a supported patched release, and rerun the scan."
            )
        ).strip()

    if description:
        return (
            f"{description} Review the evidence and affected location to confirm "
            "the finding applies to this application."
        )
    return (
        "The scanner reported a possible security issue, but its output does not "
        "include enough context to identify the root cause. Review the affected "
        "location and evidence before deciding whether it applies."
    )


def _finding_remediation(finding: Dict[str, Any]) -> str:
    remediation = str(finding.get("ai_remediation") or "").strip()
    recommendation = str(finding.get("recommendation") or "").strip()
    if remediation and remediation.lower() not in {
        "review the finding and apply security best practices.",
        "review the evidence and recommendation for details.",
    } and remediation != recommendation:
        return remediation

    title = str(finding.get("title") or "").lower()
    category = str(finding.get("category") or "").lower()
    if category == "secrets" or "password" in title or "secret" in title:
        return (
            "1. Open the reported file and remove the credential from the source.\n"
            "2. If the value is real, revoke or rotate it now; deleting it from the "
            "latest version alone does not invalidate it or remove it from Git history.\n"
            "3. Load the replacement from an environment variable or an approved "
            "secrets manager. Keep local secret files out of version control.\n"
            "4. Run the application and scan again. Confirm the secret is no longer "
            "detected and the affected login or integration still works."
        )
    if recommendation:
        return (
            f"{recommendation}\n\nAfter applying the change, run the relevant tests "
            "and repeat the scan to verify the issue is resolved."
        )
    return (
        "Review the affected code and apply the smallest safe change that removes "
        "the reported risk. Run the relevant tests, then repeat the scan to verify "
        "the finding no longer appears."
    )


def render_finding_card(
    f: Dict[str, Any],
    *,
    scan_id: Optional[str] = None,
    github_url: Optional[str] = None,
    github_token: str = "",
    ai_consent: bool = False,
) -> None:
    sev = str(f.get("severity", "info")).lower()
    status = str(f.get("status", "manual_review")).lower()
    title = str(f.get("title", "Untitled"))
    file_info = f.get("file", "")
    if file_info and f.get("line"):
        file_info = f"{file_info}:{f['line']}"

    with st.container(border=True):
        title_col, badge_col = st.columns([5, 1])
        with title_col:
            st.markdown(f"#### {title}")
        with badge_col:
            st.markdown(
                f"<div style='text-align:right;padding-top:.45rem'>"
                f"{sev_badge(sev)}</div>",
                unsafe_allow_html=True,
            )
        meta = [f"Review status: {status.replace('_', ' ').title()}"]
        if file_info:
            meta.append(file_info)
        if f.get("confidence"):
            meta.append(f"Confidence: {str(f['confidence']).title()}")
        st.caption(" · ".join(meta))

        if f.get("package"):
            package = f.get("package")
            version = f.get("installed_version") or "version unknown"
            fixed = f.get("fixed_version")
            st.info(
                f"Affected dependency: **{package}** ({version})"
                + (f" · Suggested upgrade: **{fixed}**" if fixed else ""),
                icon="📦",
            )
            if f.get("cve_id"):
                st.caption(f"Advisory: {f['cve_id']}")

        explanation = _finding_explanation(f)
        remediation = _finding_remediation(f)
        cause_col, fix_col = st.columns(2, gap="medium")
        with cause_col:
            st.markdown("**Why this was flagged**")
            st.write(explanation)
        with fix_col:
            st.markdown("**How to fix it**")
            st.markdown(remediation)

        evidence = str(f.get("evidence") or "").strip()
        if evidence:
            if evidence == "[SECRET VALUE REDACTED]":
                evidence = "Sensitive value hidden. Review the file and line above."
            st.markdown("**Evidence**")
            st.code(evidence[:1200], language="text")

        if scan_id and github_url and f.get("file"):
            finding_id = str(f.get("id") or "")
            category = str(f.get("category") or "").lower()
            if category == "secrets" or any(
                word in title.lower()
                for word in ("secret", "password", "token", "credential", "api key")
            ):
                st.warning(
                    "This finding cannot be auto-fixed safely. Rotate any real credential "
                    "first; the scanner will not send this file to AI or create a PR for it."
                )
            elif finding_id:
                draft_key = f"fix_draft_{scan_id}_{finding_id}"
                draft = st.session_state.get(draft_key)
                if st.button(
                    "Generate fix preview",
                    key=f"draft_fix_{scan_id}_{finding_id}",
                    disabled=not (github_token and ai_consent),
                    help=(
                        "Drafts a change for review. The affected file is sent to the configured "
                        "AI service only after you consent."
                    ),
                ):
                    with st.spinner("Preparing a fix preview..."):
                        draft = api_draft_fix(scan_id, finding_id, github_token)
                    if draft:
                        st.session_state[draft_key] = draft
                        st.rerun()

                if draft:
                    diff = difflib.unified_diff(
                        str(draft["original_content"]).splitlines(),
                        str(draft["updated_content"]).splitlines(),
                        fromfile=f"a/{draft['file']}",
                        tofile=f"b/{draft['file']}",
                        lineterm="",
                    )
                    st.caption(
                        f"Preview for `{draft['file']}` on `{draft['default_branch']}`. "
                        "Review the complete diff before opening a PR."
                    )
                    st.code("\n".join(diff), language="diff")
                    approved = st.checkbox(
                        "I reviewed this diff and want to open a pull request.",
                        key=f"approve_fix_{scan_id}_{finding_id}_{draft['draft_id']}",
                    )
                    if st.button(
                        "Create pull request",
                        key=f"create_fix_pr_{scan_id}_{finding_id}",
                        type="primary",
                        disabled=not (approved and github_token),
                    ):
                        with st.spinner("Creating a branch and pull request..."):
                            result = api_create_fix_pr(
                                scan_id,
                                finding_id,
                                draft["draft_id"],
                                github_token,
                            )
                        if result:
                            st.session_state.pop(draft_key, None)
                            st.success("Pull request created. Review and test it before merging.")
                            st.markdown(
                                f"[Open pull request]({result['pull_request_url']})"
                            )

def scan_limit_rows() -> List[Dict[str, str]]:
    """Return user-facing explanations for the limits enforced by the app."""
    return [
        {
            "Default": f"{MAX_REPO_SIZE_BYTES // (1024 * 1024)} MB per repository",
            "Why it exists": "Keeps clone size, disk use, and scan time bounded.",
            "If reached": "Choose a smaller repository; raise the limit only if the host has enough resources.",
        },
        {
            "Default": f"{MAX_FINDINGS_PER_AGENT} findings per scanner",
            "Why it exists": "Prevents noisy or unusually large scan output from overwhelming triage.",
            "If reached": "Review high-severity results first and narrow the scanned project where possible.",
        },
        {
            "Default": f"{GIT_CLONE_TIMEOUT_SECONDS} seconds per clone",
            "Why it exists": "Stops a stalled or very slow repository download from hanging the scan.",
            "If reached": "Check network access and repository availability, then retry.",
        },
        {
            "Default": f"{AGENT_TIMEOUT_SECONDS} seconds per scanner",
            "Why it exists": "Bounds the time a security tool can consume on one scan.",
            "If reached": "Retry with a smaller target; investigate tool or host performance before increasing it.",
        },
        {
            "Default": f"{HTTP_REQUEST_TIMEOUT} seconds per outbound request",
            "Why it exists": "Keeps external API and website checks responsive.",
            "If reached": "Check that the target is reachable and retry; slow targets may need investigation.",
        },
        {
            "Default": "5 simultaneous scan workers",
            "Why it exists": "Limits concurrent background work to protect application resources.",
            "If reached": "Wait for a running scan to finish before starting another.",
        },
    ]


def scan_error_guidance(error: str) -> Optional[Dict[str, str]]:
    """Translate common scan errors into a cause and a user-facing next step."""
    message = error.lower()
    if "repository is too large" in message:
        return {
            "reason": "The repository is larger than this installation's scan limit.",
            "resolution": (
                "Choose a smaller repository, or ask the administrator to raise "
                "the repository size limit if the server has enough disk space."
            ),
        }
    if "access denied" in message or "repository not found" in message:
        return {
            "reason": "GitHub could not give the configured account access to this repository.",
            "resolution": (
                "Check the repository URL and confirm your GitHub account has access. "
                "For a private repository, ask the administrator to configure a "
                "least-privilege token for that repository on the backend."
            ),
        }
    if "timed out" in message:
        return {
            "reason": "A download, network request, or scan exceeded its time limit.",
            "resolution": (
                "Confirm the target is reachable, retry, and try a smaller target "
                "if it times out again."
            ),
        }
    if "invalid" in message:
        return {
            "reason": "The submitted address could not be validated.",
            "resolution": "Check the URL and use a GitHub repository or website address.",
        }
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # ── Hero header ───────────────────────────────────────────────────────────
    st.markdown("""
    <div class="hero-header">
        <h1 class="hero-title">🛡️ CypherX</h1>
        <p class="hero-subtitle">Detect. Analyze. Protect.</p>
    </div>
    """, unsafe_allow_html=True)
    st.caption("Scan only repositories and websites you own or are authorized to assess.")

    # ── Session state ─────────────────────────────────────────────────────────
    if "scan_id" not in st.session_state:
        st.session_state.scan_id = None
    if "scan_data" not in st.session_state:
        st.session_state.scan_data = None
    if "polling" not in st.session_state:
        st.session_state.polling = False

    # ── Input panel ───────────────────────────────────────────────────────────
    with st.container(border=True):
        st.markdown(
            "### What would you like to check?",
            help="Enter a repository URL, website URL, or both.",
        )
        st.caption("You can scan one target or provide both for a combined review.")

        col1, col2 = st.columns(2)
        with col1:
            github_url = st.text_input(
                "GitHub repository (optional)",
                placeholder="https://github.com/owner/repo",
                label_visibility="visible",
                key="github_input",
            )
        with col2:
            website_url = st.text_input(
                "Website URL (optional)",
                placeholder="https://example.com",
                label_visibility="visible",
                key="website_input",
            )

        btn_col, _ = st.columns([1, 2])
        with btn_col:
            scan_clicked = st.button("Start scan", key="scan_btn", type="primary")

    if scan_clicked:
        if not github_url.strip() and not website_url.strip():
            st.warning("Please enter at least one URL to scan.")
        else:
            scan_id = api_start_scan(
                github_url.strip() or None,
                website_url.strip() or None,
            )
            if scan_id:
                st.session_state.scan_id = scan_id
                st.session_state.scan_data = None
                st.session_state.polling = True
                st.rerun()

    # ── Results panel ─────────────────────────────────────────────────────────
    if st.session_state.scan_id:
        scan_id = st.session_state.scan_id

        # Poll the API
        scan_data = api_get_scan(scan_id)
        if scan_data:
            st.session_state.scan_data = scan_data

        data = st.session_state.scan_data or {}
        status = data.get("status", "running")

        # ── Status bar ────────────────────────────────────────────────────────
        st.markdown("## Scan results")
        status_col, id_col = st.columns([3, 1])
        with status_col:
            status_labels = {
                "running": "Scan in progress",
                "completed": "Scan complete",
                "failed": "Scan failed",
                "partial": "Scan incomplete",
                "pending": "Scan queued",
            }
            st.markdown(f"### {status_labels.get(status, 'Scan status unavailable')}")
        with id_col:
            st.caption(f"Scan ID: `{scan_id}`")

        # Spinner while running
        if status == "running":
            with st.spinner("Reviewing the target. Results will appear here when the scan finishes."):
                time.sleep(3)
            st.rerun()

        # ── Completed results ─────────────────────────────────────────────────
        if status in ("completed", "partial"):
            findings: List[Dict] = data.get("verified_findings", [])
            errors: List[str] = data.get("errors", [])

            # Explain scan issues in plain language and provide next steps.
            if errors:
                for index, err in enumerate(errors[:5], start=1):
                    guidance = scan_error_guidance(err)
                    if guidance:
                        st.error(f"Check {index}: {guidance['reason']}")
                        st.markdown(f"**How to resolve it:** {guidance['resolution']}")
                    else:
                        st.error(f"Check {index} could not complete.")
                        st.caption(f"Details: {err}")
                        st.markdown(
                            "**How to resolve it:** Review the scan configuration and "
                            "logs, correct the reported problem, then run the scan again."
                        )

            if status == "partial":
                st.warning(
                    "Some checks did not finish. Treat these results as incomplete, "
                    "not as confirmation that the target is secure."
                )

            # ── Overview metrics ──────────────────────────────────────────────
            total = len(findings)
            critical_high = sum(1 for f in findings if f.get("severity") in ("critical", "high"))

            m1, m2, m3 = st.columns(3)
            for col, value, label in [
                (m1, total, "Issues found"),
                (m2, critical_high, "High priority"),
                (m3, total - critical_high, "Other issues"),
            ]:
                with col:
                    st.markdown(
                        f'<div class="metric-tile">'
                        f'<div class="metric-value">{value}</div>'
                        f'<div class="metric-label">{label}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

            if critical_high:
                st.info(
                    f"{critical_high} high-priority issue(s) should be reviewed first. "
                    "Each result below includes the reason it was flagged and steps to resolve it."
                )

            # ── Findings list ───────────────────────────────────────────────────
            if findings:
                st.markdown("### Findings")
                github_url = data.get("github_url")
                fixable_findings = [
                    finding for finding in findings
                    if github_url
                    and finding.get("file")
                    and str(finding.get("category") or "").lower() != "secrets"
                    and not any(
                        word in str(finding.get("title") or "").lower()
                        for word in ("secret", "password", "token", "credential", "api key")
                    )
                ]
                github_token = ""
                ai_consent = False
                if fixable_findings:
                    with st.expander("Prepare a reviewed fix pull request"):
                        st.caption(
                            "CypherX can draft a change for a code finding, show you the diff, "
                            "and open a pull request only after your approval. It never pushes "
                            "to the default branch. Secret findings require manual rotation."
                        )
                        if not _api_can_receive_github_token():
                            st.error(
                                "Configure API_BASE_URL as HTTPS before sending a GitHub token. "
                                "Localhost is also allowed for development."
                            )
                        token_key = f"github_fix_token_{scan_id}"
                        github_token = st.text_input(
                            "Fine-grained GitHub token",
                            type="password",
                            key=token_key,
                            help=(
                                "Use a short-lived token scoped to this repository with "
                                "Contents read/write and Pull requests write permissions."
                            ),
                        )
                        st.button(
                            "Clear GitHub token",
                            key=f"clear_github_fix_token_{scan_id}",
                            on_click=lambda key=token_key: st.session_state.__setitem__(key, ""),
                            disabled=not github_token,
                        )
                        ai_consent = st.checkbox(
                            "I consent to sending the affected source file to the configured "
                            "Gemini AI service to draft a fix.",
                            key=f"ai_fix_consent_{scan_id}",
                        )
                severities = ["All priorities", "Critical", "High", "Medium", "Low", "Info"]
                severity_filter = st.selectbox(
                    "Show",
                    severities,
                    key=f"filter_{scan_id}",
                    label_visibility="collapsed",
                )
                filtered = (
                    findings
                    if severity_filter == "All priorities"
                    else [
                        finding for finding in findings
                        if str(finding.get("severity", "")).lower() == severity_filter.lower()
                    ]
                )
                st.caption(f"Showing {len(filtered)} of {total} findings")
                for finding in filtered:
                    render_finding_card(
                        finding,
                        scan_id=scan_id,
                        github_url=github_url,
                        github_token=github_token,
                        ai_consent=ai_consent,
                    )

            elif status == "completed" and not errors:
                st.success(
                    "No issues were found by the checks that ran. This does not guarantee "
                    "that the target has no security issues.",
                )
            elif status == "partial":
                st.warning(
                    "No findings were returned by the checks that ran. Because the scan "
                    "was incomplete, this is not a clean result."
                )

            # ── Download buttons ──────────────────────────────────────────────
            if data.get("report_json_path") or data.get("report_pdf_path"):
                st.markdown("### 📥 Download Reports")
                dl1, dl2 = st.columns(2)
                with dl1:
                    if data.get("report_json_path"):
                        st.link_button(
                            "⬇️ Download JSON Report",
                            f"{API_BASE}/scan/{scan_id}/report/json",
                            width="stretch",
                        )
                with dl2:
                    if data.get("report_pdf_path"):
                        st.link_button(
                            "📄 Download PDF Report",
                            f"{API_BASE}/scan/{scan_id}/report/pdf",
                            width="stretch",
                        )

        elif status == "failed":
            errors = data.get("errors", [])
            st.error("The scan could not be completed.")
            if not errors:
                st.markdown(
                    "**How to resolve it:** Check that the target is reachable and "
                    "the scanner is configured correctly, then try again."
                )
            for index, err in enumerate(errors, start=1):
                guidance = scan_error_guidance(err)
                if guidance:
                    st.markdown(f"**Issue {index}:** {guidance['reason']}")
                    st.markdown(f"**How to resolve it:** {guidance['resolution']}")
                else:
                    st.markdown(f"**Issue {index}:** {err}")
                    st.markdown(
                        "**How to resolve it:** Review the server logs for this issue, "
                        "correct the cause, and run the scan again."
                    )

        with st.expander("About scan limits"):
            st.caption(
                "Limits keep scans responsive and prevent excessive resource use. "
                "If a limit interrupts a scan, the results are marked incomplete."
            )
            st.table(scan_limit_rows())

        # ── New scan button ───────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔄 Start New Scan", key="new_scan"):
            st.session_state.scan_id = None
            st.session_state.scan_data = None
            st.session_state.polling = False
            st.rerun()


if __name__ == "__main__":
    main()
