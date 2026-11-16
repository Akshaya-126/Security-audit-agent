# 🛡️ CypherX — Detect. Analyze. Protect.

An AI-driven cybersecurity platform that automatically analyzes GitHub repositories and live websites to identify security vulnerabilities, evaluate their severity, and recommend remediation steps.

## Architecture

```
User Input (Streamlit)
       ↓
FastAPI Backend
       ↓
LangGraph Orchestrator
       ↓ (parallel)
┌──────────────────────────────────────────┐
│  Code Agent  │  Dependency  │  Config    │  Website  │
│  (Semgrep +  │  Agent       │  Agent     │  Agent    │
│   Gitleaks)  │  (OSV-Scan)  │  (Checkov) │  (HTTPX)  │
└──────────────────────────────────────────┘
       ↓
Verification & Triage Agent
       ↓
Report Generation Agent (Gemini API)
       ↓
PDF / JSON Report
```

## Features

- 🔍 **Static Code Analysis** — Semgrep detects injection, XSS, and insecure patterns
- 🔑 **Secret Detection** — Gitleaks + regex scanner finds hardcoded credentials
- 📦 **Dependency Scanning** — OSV-Scanner identifies known CVEs in dependencies
- 🌐 **Website Security** — HTTPX checks headers, TLS, cookies, and HTTPS config
- 🏗️ **Config Analysis** — Checkov audits Dockerfile, Terraform, Kubernetes configs
- 🤖 **AI-Powered Reports** — Gemini explains findings in developer-friendly language
- 🛠️ **Reviewed Fix Pull Requests** — Draft a code fix, inspect its diff, and explicitly approve a branch and pull request
- ⚡ **Parallel Execution** — LangGraph runs all agents concurrently
- 📄 **Report Export** — Download PDF and JSON audit reports

### Reviewed code fixes

For eligible GitHub code findings, the dashboard can prepare a proposed file
change and show its diff. The affected file is sent to the configured Gemini
service only after you opt in. A fix is never pushed to the default branch:
you must review the diff and approve creating a separate branch and pull request.
Review and test every pull request before merging.

To use this workflow, enter a fine-grained GitHub token in the scan results
panel, scoped to the scanned repository with **Contents: read and write** and
**Pull requests: write** permissions. The token is passed to the backend for
GitHub API calls and is not saved in scan records. Use HTTPS for a remotely
hosted `API_BASE_URL`; localhost is allowed for development. Clear the token
from the dashboard when finished.

Secret findings are deliberately excluded from automated code fixes. Rotate or
revoke any real credential first, then remove it from source and configure its
replacement securely. The fix workflow does not rotate credentials or erase
repository history.

## Quick Start

### 1. Prerequisites

```bash
# Python 3.11+
python --version

# Install Python dependencies
pip install -r requirements.txt

# Optional but recommended — install binary security tools:
# Gitleaks: https://github.com/gitleaks/gitleaks/releases
# OSV-Scanner: https://github.com/google/osv-scanner/releases
# (Semgrep and Checkov are installed via pip above)
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

The default Gemini model is `gemini-3.8-flash`. If an existing `.env` specifies
an older model, update `GEMINI_MODEL` to a currently supported model.

`GITHUB_TOKEN` is optional and is only needed for private repositories your
GitHub account is already allowed to access, or to raise GitHub API rate limits.
Use a fine-grained token with read-only access to the specific repository, set
it in the backend environment, and never paste it into the dashboard or commit
it to source control. A token does not grant access to repositories that have
not granted your account permission.

### Scan limits

The scanner uses bounded defaults to avoid excessive resource use:

| Default | Why it exists | If the limit is reached |
|---|---|---|
| 200 MB maximum repository clone (`MAX_REPO_SIZE_MB`) | Bounds disk use and clone/scan time | Choose a smaller repository, or raise the setting only when the host has enough capacity |
| 500 findings per scanner | Prevents excessive scanner output from overwhelming triage | Review the highest-severity results and narrow the target |
| 120 seconds per Git clone | Stops a stalled download from hanging the scan | Check network access and repository availability, then retry |
| 300 seconds per scanner | Bounds tool execution time | Retry with a smaller target and investigate scanner/host performance |
| 30 seconds per outbound HTTP request | Keeps API and website checks responsive | Check target reachability and retry |
| 5 background scan workers | Limits simultaneous work to protect application resources | Wait for a running scan to finish |

If a scan reports errors or skipped checks, treat it as incomplete rather than a
clean security result. Resolve the displayed cause and rerun the scan.

### 3. Run the Application

**Terminal 1 — Start the FastAPI backend:**
```bash
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 — Start the Streamlit dashboard:**
```bash
streamlit run app.py
```

Then open: http://localhost:8501

## Security Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| Semgrep | Static code analysis | `pip install semgrep` ✅ |
| Checkov | IaC config analysis | `pip install checkov` ✅ |
| Gitleaks | Secret detection | Binary download (optional) |
| OSV-Scanner | Dependency vulnerabilities | Binary download (optional) |

> **Note**: Gitleaks and OSV-Scanner are optional. The system falls back to built-in regex scanners and direct OSV API queries if they are not installed.

## Project Structure

```
ai-security-audit/
├── app.py              # Streamlit dashboard
├── api.py              # FastAPI backend
├── requirements.txt
├── .env.example
│
├── src/
│   ├── agents/         # LangGraph agent nodes
│   ├── graph/          # LangGraph workflow + state
│   ├── scanners/       # Security tool wrappers
│   ├── services/       # GitHub, LLM, report services
│   ├── security/       # URL validation, redaction, limits
│   └── schemas/        # Pydantic data models
│
├── tests/
└── reports/            # Generated audit reports
```

## API Endpoints

| Method | Endpoint | Description |
|--------|---------|-------------|
| POST | `/scan` | Start a new security scan |
| GET | `/scan/{id}` | Get scan status and results |
| GET | `/scan/{id}/report/pdf` | Download PDF report |
| GET | `/scan/{id}/report/json` | Download JSON report |
| GET | `/health` | Health check |

## Running Tests

```bash
pytest tests/ -v --tb=short
```

## Safety & Ethics

- Only scans repositories and websites you have permission to audit
- Blocks private/internal IP ranges to prevent SSRF attacks
- Redacts detected secrets before including them in reports
- Uses passive scanning only — no active exploitation
- Respects GitHub API rate limits

## Technology Stack

Python · LangGraph · Gemini API · FastAPI · Streamlit · Semgrep · Gitleaks · OSV-Scanner · Checkov · HTTPX · ReportLab
