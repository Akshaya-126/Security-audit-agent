"""
GitHub repository service.

Clones public (and optionally private) GitHub repositories to a temporary
directory for scanning.  Enforces size limits and cleans up after scans.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Tuple
from urllib.parse import urlparse

import httpx

from src.security.scan_limits import GIT_CLONE_TIMEOUT_SECONDS, HTTP_REQUEST_TIMEOUT, MAX_REPO_SIZE_BYTES

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"


class GitHubServiceError(Exception):
    """Raised when repository cloning or validation fails."""


def _get_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _extract_owner_repo(github_url: str) -> Tuple[str, str]:
    parsed = urlparse(github_url)
    parts = parsed.path.strip("/").split("/")
    repo = parts[1].removesuffix(".git") if len(parts) >= 2 else ""
    if not parts[0] or not repo:
        raise GitHubServiceError(f"Cannot extract owner/repo from: {github_url}")
    return parts[0], repo


def _check_repo_size(owner: str, repo: str) -> int:
    """Return repository size in KB via the GitHub API."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    try:
        with httpx.Client(timeout=HTTP_REQUEST_TIMEOUT) as client:
            resp = client.get(url, headers=_get_headers())
            resp.raise_for_status()
            return resp.json().get("size", 0)  # GitHub reports size in KB
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 404:
            raise GitHubServiceError(f"Repository not found: {owner}/{repo}") from exc
        if status == 403:
            raise GitHubServiceError(
                f"Access denied to {owner}/{repo}. "
                "Set GITHUB_TOKEN for private repositories."
            ) from exc
        raise GitHubServiceError(f"GitHub API error ({status}): {exc}") from exc
    except Exception as exc:
        logger.warning("Could not check repo size via API: %s", exc)
        return 0  # Unknown size — allow clone attempt


def clone_repository(github_url: str) -> str:
    """
    Clone a GitHub repository to a temporary directory.

    Returns the path to the clone directory.
    Raises GitHubServiceError on failure.
    """
    owner, repo = _extract_owner_repo(github_url)

    # Size check
    size_kb = _check_repo_size(owner, repo)
    size_bytes = size_kb * 1024
    if size_bytes > MAX_REPO_SIZE_BYTES:
        raise GitHubServiceError(
            f"Repository is too large ({size_kb // 1024} MB). "
            f"Maximum allowed: {MAX_REPO_SIZE_BYTES // 1024 // 1024} MB."
        )

    temp_dir = tempfile.mkdtemp(prefix=f"audit_{owner}_{repo}_")
    logger.info("Cloning %s/%s → %s", owner, repo, temp_dir)

    # Build clone URL — embed token for private repos
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        clone_url = f"https://{token}@github.com/{owner}/{repo}.git"
    else:
        clone_url = f"https://github.com/{owner}/{repo}.git"

    try:
        result = subprocess.run(
            [
                "git", "clone",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                clone_url,
                temp_dir,
            ],
            capture_output=True,
            text=True,
            timeout=GIT_CLONE_TIMEOUT_SECONDS,
        )

        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            # Sanitise error — remove token from message if present
            err_msg = result.stderr.replace(token, "***") if token else result.stderr
            raise GitHubServiceError(
                f"git clone failed: {err_msg[:300]}"
            )

        logger.info("Clone successful: %s/%s", owner, repo)
        return temp_dir

    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise GitHubServiceError(
            f"Clone timed out after {GIT_CLONE_TIMEOUT_SECONDS} seconds."
        )
    except GitHubServiceError:
        raise
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise GitHubServiceError(f"Unexpected clone error: {exc}") from exc


def cleanup_repository(repo_path: str) -> None:
    """Remove a cloned repository from the filesystem."""
    if repo_path and Path(repo_path).exists():
        try:
            shutil.rmtree(repo_path, ignore_errors=True)
            logger.info("Cleaned up: %s", repo_path)
        except Exception as exc:
            logger.warning("Cleanup failed for %s: %s", repo_path, exc)
