"""Tests for user-facing finding and scan issue explanations."""

from app import _finding_explanation, _finding_remediation, scan_error_guidance


def test_password_finding_explains_cause_and_false_positive_check():
    finding = {
        "title": "Potential Hardcoded Password",
        "category": "Secrets",
        "description": "A pattern matching a hardcoded password was found.",
        "ai_explanation": (
            "This is a high severity Secrets issue. Review the evidence and "
            "recommendation for details."
        ),
    }

    explanation = _finding_explanation(finding)

    assert "assigned directly in a source file" in explanation
    assert "false positives" in explanation


def test_password_finding_lists_concrete_fix_steps():
    remediation = _finding_remediation({
        "title": "Potential Hardcoded Password",
        "category": "Secrets",
        "recommendation": "Move this secret to an environment variable.",
        "ai_remediation": "Move this secret to an environment variable.",
    })

    assert "revoke or rotate it" in remediation
    assert "Git history" in remediation
    assert "scan again" in remediation


def test_large_repository_error_has_cause_and_resolution():
    guidance = scan_error_guidance("Clone failed: Repository is too large (1668 MB).")

    assert guidance is not None
    assert "scan limit" in guidance["reason"]
    assert "smaller repository" in guidance["resolution"]
