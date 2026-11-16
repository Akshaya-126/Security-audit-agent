"""
Tests for the Finding schema and related utilities.
"""

import pytest

from src.schemas.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Severity,
    ScanRequest,
)
from src.scanners.secret_scanner import has_secret_like_value
from src.security.redaction import redact_finding, redact_string


class TestFindingModel:
    """Unit tests for the Finding Pydantic model."""

    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            title="Test Finding",
            category="Injection",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="A test SQL injection finding.",
            evidence="SELECT * FROM users WHERE id = '" + "' + user_input",
            recommendation="Use parameterized queries.",
            source="Semgrep",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_finding_creation(self):
        f = self._make_finding()
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.status == FindingStatus.MANUAL_REVIEW  # default

    def test_finding_to_dict(self):
        f = self._make_finding()
        d = f.to_dict()
        assert isinstance(d, dict)
        assert d["title"] == "Test Finding"
        assert d["severity"] == "high"

    def test_finding_from_dict_roundtrip(self):
        f = self._make_finding(file="src/app.py", line=42)
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.title == f.title
        assert f2.file == "src/app.py"
        assert f2.line == 42

    def test_finding_severity_values(self):
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            f = self._make_finding(severity=sev)
            assert f.severity == sev

    def test_finding_optional_fields_default_none(self):
        f = self._make_finding()
        assert f.file is None
        assert f.line is None
        assert f.cve_id is None
        assert f.ai_explanation is None

    def test_finding_with_package_info(self):
        f = self._make_finding(
            category="Vulnerable Dependency",
            package="requests",
            installed_version="2.25.0",
            fixed_version="2.28.0",
            cve_id="CVE-2023-32681",
        )
        assert f.package == "requests"
        assert f.cve_id == "CVE-2023-32681"

    def test_finding_id_is_unique(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.id != f2.id

    def test_finding_invalid_severity_raises(self):
        with pytest.raises(Exception):
            self._make_finding(severity="unknown-severity")


class TestScanRequest:
    """Unit tests for ScanRequest validation."""

    def test_scan_request_github_only(self):
        r = ScanRequest(github_url="https://github.com/owner/repo")
        assert r.github_url == "https://github.com/owner/repo"
        assert r.website_url is None

    def test_scan_request_strips_whitespace(self):
        r = ScanRequest(github_url="  https://github.com/owner/repo  ")
        assert r.github_url == "https://github.com/owner/repo"

    def test_scan_request_rejects_empty_strings_after_normalization(self):
        with pytest.raises(ValueError, match="at least one"):
            ScanRequest(github_url="   ", website_url="")

    def test_scan_request_both_urls(self):
        r = ScanRequest(
            github_url="https://github.com/owner/repo",
            website_url="https://example.com",
        )
        assert r.github_url is not None
        assert r.website_url is not None

    def test_scan_request_requires_at_least_one_target(self):
        with pytest.raises(ValueError, match="at least one"):
            ScanRequest()


class TestRedaction:
    """Unit tests for secret redaction utilities."""

    def test_aws_key_redacted(self):
        text = "key = AKIAIOSFODNN7EXAMPLE"
        result = redact_string(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_github_token_redacted(self):
        text = "token = ghp_abcdefghijklmnopqrstuvwxyz12345"
        result = redact_string(text)
        assert "ghp_" not in result

    def test_google_api_key_redacted(self):
        text = "AIzaSyAbcdefghijklmnopqrstuvwxyz12345678"
        result = redact_string(text)
        assert "AIzaSy" not in result

    def test_password_redacted(self):
        text = 'password = "supersecretpassword123"'
        result = redact_string(text)
        assert "supersecretpassword123" not in result

    def test_non_secret_string_unchanged(self):
        text = "print('Hello, World!')"
        result = redact_string(text)
        assert result == text

    def test_secret_scanner_detects_secret_like_file_content(self):
        assert has_secret_like_value('db_password = "example-secret-value"')
        assert not has_secret_like_value("print('hello world')")

    def test_finding_evidence_redacted(self):
        finding = {
            "title": "Hardcoded Secret",
            "evidence": "api_key = AKIAIOSFODNN7EXAMPLE",
        }
        redacted = redact_finding(finding)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted["evidence"]

    def test_nested_finding_redacted(self):
        finding = {
            "title": "Test",
            "nested": {
                "value": "password='mysecretpassword'"
            }
        }
        redacted = redact_finding(finding)
        assert "mysecretpassword" not in str(redacted)
