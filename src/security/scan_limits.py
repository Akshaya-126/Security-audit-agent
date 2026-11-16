"""
Scan resource limits and safety thresholds.

Centralising limits here makes it easy to adjust them without hunting
through scanner code.
"""

import os

# ── Repository limits ─────────────────────────────────────────────────────────

# Maximum repository size to clone (bytes). Default: 200 MB.
MAX_REPO_SIZE_MB: int = int(os.environ.get("MAX_REPO_SIZE_MB", "200"))
if MAX_REPO_SIZE_MB < 1:
    raise ValueError("MAX_REPO_SIZE_MB must be a positive integer.")
MAX_REPO_SIZE_BYTES: int = MAX_REPO_SIZE_MB * 1024 * 1024

# Maximum number of files passed to any single scanner
MAX_FILES_PER_SCAN: int = 2_000

# Maximum number of raw findings returned by a single scanner
MAX_FINDINGS_PER_AGENT: int = 500

# ── Timeout limits ────────────────────────────────────────────────────────────

# Maximum time (seconds) for a single agent / subprocess tool to complete
AGENT_TIMEOUT_SECONDS: int = 300  # 5 minutes

# Maximum time (seconds) for the full scan workflow
TOTAL_SCAN_TIMEOUT_SECONDS: int = 900  # 15 minutes

# Git clone timeout (seconds)
GIT_CLONE_TIMEOUT_SECONDS: int = 120

# ── HTTP limits ───────────────────────────────────────────────────────────────

# Timeout for a single outbound HTTP request (seconds)
HTTP_REQUEST_TIMEOUT: int = 30

# Maximum website response body to inspect (bytes). Default: 5 MB.
MAX_WEBSITE_RESPONSE_BYTES: int = 5 * 1024 * 1024

# ── Concurrency limits ────────────────────────────────────────────────────────

# Maximum number of simultaneous scan workflows (for future rate-limiting)
MAX_CONCURRENT_SCANS: int = 5

# ── ZAP limits (optional integration) ────────────────────────────────────────

ZAP_SCAN_TIMEOUT_SECONDS: int = 120
