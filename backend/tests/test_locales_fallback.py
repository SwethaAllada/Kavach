"""Fallback-safety tests for core.locales_loader — the hard requirement that
wiring locales/ into the request path can never break /analyze or /webhook.

Contract under test: requested language -> English -> caller default. A
missing key, a missing language, or a locale that omits an entire section
must never raise and must never silently return an empty string when a
default is supplied.
"""

from __future__ import annotations

from core.locales_loader import SUPPORTED_LANGUAGES, get_string
from services.classifier import _fallback_from_rules, _safe_verdict
from services.report import build_report
from services.whatsapp_format import verdict_to_whatsapp_text


def test_missing_key_falls_back_to_default():
    result = get_string("en", "fallback_templates", "no_such_scam_type", "explanation", default="SAFE")
    assert result == "SAFE"


def test_unregistered_language_falls_back_to_english():
    # "fr" is not a registered locale; a real English key must still resolve.
    result = get_string("fr", "fallback_templates", "other", "explanation", default="SAFE")
    assert result != "SAFE"
    assert "suspicious" in result.lower()


def test_renamed_key_falls_back_to_default_not_crash():
    # Simulates a locale file where a key was renamed/typo'd — get_string
    # must not raise, and must return the default rather than None/"".
    result = get_string("hi", "report", "ask_clause", "totally_made_up_key", default="fallback text")
    assert result == "fallback text"


def test_get_string_never_raises_on_malformed_input():
    # Path segments that don't exist at all, on every registered language.
    for lang in SUPPORTED_LANGUAGES:
        result = get_string(lang, "does", "not", "exist", "at", "all", default="OK")
        assert result == "OK"
    # Empty language string, no path at all.
    assert get_string("", default="OK") == "OK"


def test_classifier_fallback_survives_missing_locale_language():
    rules_out = {"scam_type": "kyc_bank", "rule_risk": 60, "signals": []}
    out = _fallback_from_rules(rules_out, "text", "xx")  # unregistered language
    assert out["explanation"]
    assert out["recommended_action"]


def test_classifier_safe_verdict_never_empty():
    out = _safe_verdict("text", "xx")
    assert out["explanation"]
    assert out["recommended_action"]


def test_report_build_report_survives_unregistered_language():
    verdict = {
        "scam_type": "kyc_bank",
        "risk": 80,
        "signals": ["credential_request"],
        "detected_language": "xx",  # not a registered locale
    }
    out = build_report(verdict, "some suspicious text")
    assert out["prefilled_summary"]  # never empty when should_report is True
    assert out["evidence_checklist"]


def test_whatsapp_format_survives_unregistered_language():
    verdict = {
        "scam_type": "kyc_bank",
        "risk": 80,
        "detected_language": "xx",
        "explanation": "x",
        "recommended_action": "y",
    }
    text = verdict_to_whatsapp_text(verdict)
    assert text
    assert "Kavach" in text  # brand string resolved, not empty/crashed


def test_whatsapp_format_survives_completely_malformed_verdict():
    # Not a dict, missing scam_type, None — none of these may raise.
    assert verdict_to_whatsapp_text({}) != ""
    assert verdict_to_whatsapp_text(None) != ""
