"""HTTP contract tests for the FastAPI endpoints."""

from fastapi.testclient import TestClient

from api import app
import api as api_module

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_rejects_empty_target():
    response = client.post("/scan", json={})

    assert response.status_code == 422
    assert "at least one" in response.text.lower()


def test_fix_draft_requires_explicit_ai_consent(monkeypatch):
    api_module._scans["test-scan"] = {
        "status": "completed",
        "github_url": "https://github.com/example/project",
        "verified_findings": [{
            "id": "finding-1",
            "title": "Unsafe query",
            "category": "Injection",
            "file": "src/query.py",
        }],
    }
    monkeypatch.setattr(
        api_module,
        "fetch_file_for_draft",
        lambda *_args: (_ for _ in ()).throw(AssertionError("must not fetch without consent")),
    )

    response = client.post(
        "/scan/test-scan/findings/finding-1/fix-draft",
        json={"github_token": "x" * 24, "consent_to_ai": False},
    )

    assert response.status_code == 422


def test_secret_finding_cannot_be_automatically_drafted():
    api_module._scans["test-secret-scan"] = {
        "status": "completed",
        "github_url": "https://github.com/example/project",
        "verified_findings": [{
            "id": "secret-1",
            "title": "Potential Hardcoded Password",
            "category": "Secrets",
            "file": "src/config.py",
        }],
    }

    response = client.post(
        "/scan/test-secret-scan/findings/secret-1/fix-draft",
        json={"github_token": "x" * 24, "consent_to_ai": True},
    )

    assert response.status_code == 422
    assert "manual" in response.json()["detail"].lower()


def test_reviewed_draft_can_create_pull_request(monkeypatch):
    api_module._scans["test-pr-scan"] = {
        "status": "completed",
        "github_url": "https://github.com/example/project",
        "verified_findings": [{
            "id": "finding-pr",
            "title": "Unsafe query",
            "category": "Injection",
            "file": "src/query.py",
        }],
    }
    monkeypatch.setattr(
        api_module,
        "fetch_file_for_draft",
        lambda *_args: {
            "owner": "example",
            "repo": "project",
            "default_branch": "main",
            "file_path": "src/query.py",
            "file_sha": "abc123",
            "source": "query = input()\n",
        },
    )
    monkeypatch.setattr(api_module, "draft_code_fix", lambda *_args: "query = safe_query()\n")
    monkeypatch.setattr(
        api_module,
        "create_fix_pull_request",
        lambda *_args: {
            "pull_request_url": "https://github.com/example/project/pull/42",
            "branch": "cypherx/security-fix-test",
        },
    )

    draft_response = client.post(
        "/scan/test-pr-scan/findings/finding-pr/fix-draft",
        json={"github_token": "x" * 24, "consent_to_ai": True},
    )
    assert draft_response.status_code == 200
    draft = draft_response.json()
    assert draft["original_content"] != draft["updated_content"]

    response = client.post(
        "/scan/test-pr-scan/findings/finding-pr/pull-request",
        params={"draft_id": draft["draft_id"]},
        json={"github_token": "x" * 24, "approved": True},
    )

    assert response.status_code == 200
    assert response.json()["pull_request_url"].endswith("/pull/42")
