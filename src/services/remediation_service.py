"""GitHub-backed, user-approved security fix pull requests."""

from __future__ import annotations

import base64
import uuid
from pathlib import PurePosixPath
from typing import Any, Dict
from urllib.parse import quote

import httpx

from src.security.redaction import redact_string
from src.security.url_validator import validate_github_url
from src.scanners.secret_scanner import has_secret_like_value

GITHUB_API_BASE = "https://api.github.com"
MAX_FIX_FILE_BYTES = 100_000


class RemediationError(Exception):
    """Raised when a safe fix draft or pull request cannot be created."""


def _headers(token: str) -> Dict[str, str]:
    if not token.strip():
        raise RemediationError("A GitHub token is required for repository access.")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token.strip()}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _repo_parts(github_url: str) -> tuple[str, str]:
    valid, error, owner, repo = validate_github_url(github_url)
    if not valid or not owner or not repo:
        raise RemediationError(error or "The scan does not contain a valid GitHub repository.")
    return owner, repo


def _github_json(
    client: httpx.Client,
    method: str,
    url: str,
    token: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    try:
        response = client.request(method, url, headers=_headers(token), **kwargs)
    except httpx.HTTPError as exc:
        raise RemediationError("Could not reach the GitHub API. Check the connection and try again.") from exc

    if response.is_error:
        status = response.status_code
        if status == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            raise RemediationError("GitHub API rate limit reached. Wait and try again.")
        if status in {401, 403}:
            raise RemediationError(
                "GitHub denied this operation. Use a fine-grained token with access "
                "to this repository and Contents (read/write) and Pull requests (write) permissions."
            )
        if status == 404:
            raise RemediationError(
                "GitHub could not find this repository or file for the supplied token."
            )
        if status == 409:
            raise RemediationError(
                "The repository changed while preparing the fix. Generate a fresh preview and try again."
            )
        if status == 422:
            raise RemediationError(
                "GitHub rejected the requested branch, commit, or pull request. "
                "Check whether a matching pull request already exists."
            )
        if status == 429:
            raise RemediationError("GitHub API rate limit reached. Wait and try again.")
        raise RemediationError(f"GitHub API returned HTTP {status}.")

    try:
        value = response.json()
    except ValueError as exc:
        raise RemediationError("GitHub returned an unexpected response.") from exc
    if not isinstance(value, dict):
        raise RemediationError("GitHub returned an unexpected response.")
    return value


def _safe_file_path(file_path: str) -> str:
    if not file_path or "\\" in file_path or "\x00" in file_path:
        raise RemediationError("The finding does not contain a safe repository file path.")
    path = PurePosixPath(file_path)
    if str(path) in {"", "."} or path.is_absolute() or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise RemediationError("The finding does not contain a safe repository file path.")
    return str(path)


def fetch_file_for_draft(
    github_url: str,
    file_path: str,
    token: str,
) -> Dict[str, Any]:
    """Fetch a text file and its current GitHub version for a proposed fix."""
    owner, repo = _repo_parts(github_url)
    safe_path = _safe_file_path(file_path)
    name = PurePosixPath(safe_path).name.lower()
    if (
        name.startswith(".env")
        or name in {".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"}
        or PurePosixPath(name).suffix in {".pem", ".key", ".p12", ".pfx", ".tfvars"}
    ):
        raise RemediationError(
            "This file may contain credentials or private keys and is not eligible for an AI fix."
        )
    encoded_path = quote(safe_path, safe="/")
    repo_api = f"{GITHUB_API_BASE}/repos/{quote(owner)}/{quote(repo)}"

    with httpx.Client(timeout=20) as client:
        repository = _github_json(client, "GET", repo_api, token)
        default_branch = repository.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            raise RemediationError("GitHub did not provide the repository's default branch.")
        file_data = _github_json(
            client,
            "GET",
            f"{repo_api}/contents/{encoded_path}",
            token,
            params={"ref": default_branch},
        )

    if file_data.get("type") != "file" or file_data.get("encoding") != "base64":
        raise RemediationError("Only ordinary text files can be prepared for an automated fix.")
    encoded_content = file_data.get("content")
    sha = file_data.get("sha")
    if not isinstance(encoded_content, str) or not isinstance(sha, str):
        raise RemediationError("GitHub did not return the file content and version.")

    try:
        raw_content = base64.b64decode(encoded_content, validate=False)
        if len(raw_content) > MAX_FIX_FILE_BYTES:
            raise RemediationError("The affected file is too large for a reviewed fix preview.")
        source = raw_content.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise RemediationError("The affected file is not a supported UTF-8 text file.") from exc

    if redact_string(source) != source or has_secret_like_value(source):
        raise RemediationError(
            "This file appears to contain a secret. Its contents will not be sent to the AI service; "
            "remove and rotate the credential manually before requesting an automated fix."
        )

    return {
        "owner": owner,
        "repo": repo,
        "default_branch": default_branch,
        "file_path": safe_path,
        "file_sha": sha,
        "source": source,
    }


def create_fix_pull_request(
    repository: Dict[str, Any],
    updated_content: str,
    finding: Dict[str, Any],
    token: str,
) -> Dict[str, str]:
    """Create a dedicated branch and PR after the user approves a reviewed draft."""
    owner = repository["owner"]
    repo = repository["repo"]
    default_branch = repository["default_branch"]
    file_path = _safe_file_path(repository["file_path"])
    file_sha = repository["file_sha"]
    repo_api = f"{GITHUB_API_BASE}/repos/{quote(owner)}/{quote(repo)}"
    encoded_path = quote(file_path, safe="/")

    updated_bytes = updated_content.encode("utf-8")
    if len(updated_bytes) > MAX_FIX_FILE_BYTES:
        raise RemediationError("The proposed file is too large to commit.")
    if updated_content == repository["source"]:
        raise RemediationError("The proposed change is identical to the current file.")
    finding_title = (
        " ".join(str(finding.get("title") or "").replace("`", "'").split())
        or "security fix"
    )
    file_label = file_path.replace("`", "'")

    with httpx.Client(timeout=20) as client:
        current_file = _github_json(
            client,
            "GET",
            f"{repo_api}/contents/{encoded_path}",
            token,
            params={"ref": default_branch},
        )
        if current_file.get("sha") != file_sha:
            raise RemediationError(
                "The file changed after the preview was generated. Generate a fresh preview before creating a PR."
            )

        base_ref = _github_json(
            client,
            "GET",
            f"{repo_api}/git/ref/heads/{quote(default_branch, safe='')}",
            token,
        )
        base_sha = (base_ref.get("object") or {}).get("sha")
        if not isinstance(base_sha, str):
            raise RemediationError("GitHub did not return the current default branch revision.")

        branch = f"cypherx/security-fix-{uuid.uuid4().hex[:10]}"
        _github_json(
            client,
            "POST",
            f"{repo_api}/git/refs",
            token,
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
        _github_json(
            client,
            "PUT",
            f"{repo_api}/contents/{encoded_path}",
            token,
            json={
                "message": f"Fix security finding: {finding_title[:100]}",
                "content": base64.b64encode(updated_bytes).decode("ascii"),
                "sha": file_sha,
                "branch": branch,
            },
        )
        pull_request = _github_json(
            client,
            "POST",
            f"{repo_api}/pulls",
            token,
            json={
                "title": f"CypherX: {finding_title[:180]}",
                "head": branch,
                "base": default_branch,
                "body": (
                    "This pull request contains a code change drafted from a CypherX "
                    "security finding and approved for submission by the repository user.\n\n"
                    f"- Finding: {finding_title or 'Security finding'}\n"
                    f"- Severity: {finding.get('severity', 'unknown')}\n"
                    f"- File: `{file_label}`\n\n"
                    "Please review the diff and run the project's tests before merging. "
                    "This PR does not rotate or revoke any credentials."
                ),
            },
        )

    pr_url = pull_request.get("html_url")
    if not isinstance(pr_url, str):
        raise RemediationError("GitHub created a pull request but returned no browser URL.")
    return {"pull_request_url": pr_url, "branch": branch}
