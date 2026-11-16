"""Tests for configurable Gemini model selection."""

from src.services import llm_service
from src.services.llm_service import _get_model


def test_default_model_is_current_flash(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)

    assert _get_model() == "gemini-3.8-flash"


def test_model_can_be_overridden(monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "custom-model")

    assert _get_model() == "custom-model"


def test_secret_finding_has_specific_fallback_explanation(monkeypatch):
    monkeypatch.setattr(llm_service, "_call_gemini", lambda _prompt: None)

    explanation = llm_service.explain_finding({
        "title": "Potential Hardcoded Password",
        "category": "Secrets",
        "description": "A password-like pattern was found.",
        "severity": "high",
    })

    assert "assigned directly in a source file" in explanation
    assert "false positives" in explanation
    assert "Review the evidence and recommendation" not in explanation


def test_secret_finding_has_actionable_fallback_remediation(monkeypatch):
    monkeypatch.setattr(llm_service, "_call_gemini", lambda _prompt: None)

    remediation = llm_service.suggest_remediation({
        "title": "Potential Hardcoded Password",
        "category": "Secrets",
        "recommendation": "Move this secret to environment variables.",
    })

    assert "revoke or rotate it" in remediation
    assert "Git history" in remediation
    assert "scan again" in remediation
