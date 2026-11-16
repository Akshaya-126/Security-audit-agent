import pytest

from src.services.remediation_service import (
    RemediationError,
    _headers,
    _safe_file_path,
)


def test_github_authorization_header_uses_supplied_token():
    token = "x" * 24

    assert _headers(token)["Authorization"] == f"Bearer {token}"


@pytest.mark.parametrize("file_path", ["../outside.py", "/root.py", r"..\outside.py", "."])
def test_unsafe_repository_paths_are_rejected(file_path):
    with pytest.raises(RemediationError):
        _safe_file_path(file_path)


def test_safe_repository_path_is_normalized():
    assert _safe_file_path("src/fix.py") == "src/fix.py"
