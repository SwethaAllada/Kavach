"""Tests for the 10-language expansion: script-detection regexes for the 7
new translate-on-demand languages, the placeholder-survival guardrail, and
TRANSLATION_ENABLED=False behavior.

None of these tests make a real network call to Google Translate — the
placeholder-guardrail tests mock deep_translator.GoogleTranslator, and the
TRANSLATION_ENABLED=False tests exercise the short-circuit that skips
translation entirely.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.config import settings
from core.locales_loader import SUPPORTED_LANGUAGES, _translation_cache, get_string
from services.classifier import _detect_language


@pytest.fixture(autouse=True)
def _clear_translation_cache():
    """Each test starts with a clean cache so a prior test's cached result
    can't mask a mock/flag not being applied in the current test."""
    _translation_cache.clear()
    yield
    _translation_cache.clear()


# ---------------------------------------------------------------------------
# SUPPORTED_LANGUAGES
# ---------------------------------------------------------------------------


def test_supported_languages_includes_all_ten():
    expected = {"en", "hi", "te", "ta", "kn", "ml", "bn", "mr", "gu", "pa"}
    assert expected <= set(SUPPORTED_LANGUAGES)


# ---------------------------------------------------------------------------
# Script-detection regexes — no network calls.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("உங்கள் OTP ஐ யாருடனும் பகிரவேண்டாம்.", "ta"),
        ("ನಿಮ್ಮ OTP ಅನ್ನು ಯಾರೊಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.", "kn"),
        ("നിങ്ങളുടെ OTP ആരുമായും പങ്കിടരുത്.", "ml"),
        ("আপনার OTP কারো সাথে শেয়ার করবেন না।", "bn"),
        ("તમારો OTP કોઈની સાથે શેર કરશો નહીં.", "gu"),
        ("ਆਪਣਾ OTP ਕਿਸੇ ਨਾਲ ਸਾਂਝਾ ਨਾ ਕਰੋ।", "pa"),
    ],
)
def test_script_detection_new_languages(text, expected):
    assert _detect_language(text) == expected


def test_existing_hindi_detection_unaffected():
    assert _detect_language("अपना OTP किसी के साथ साझा न करें।") == "hi"


def test_existing_telugu_detection_unaffected():
    assert _detect_language("మీ OTPని ఎవరితోనూ షేర్ చేయవద్దు.") == "te"


def test_english_detection_unaffected():
    assert _detect_language("Do not share your OTP with anyone.") == "en"


@pytest.mark.parametrize(
    "text",
    [
        "तुमचा OTP कोणालाही सांगू नका, तो गुप्त आहे.",  # contains आहे
        "ही माहिती कोणालाही देऊ नका, हे बरोबर नाही.",  # contains नाही
        "आपण ही लिंक उघडू नका.",  # contains आपण
    ],
)
def test_marathi_disambiguated_from_hindi(text):
    assert _detect_language(text) == "mr"


def test_devanagari_without_marathi_words_stays_hindi():
    # No आहे/नाही/आपण/करा present -> should NOT be misdetected as Marathi.
    assert _detect_language("आपका बैंक खाता बंद हो जाएगा, तुरंत केवाईसी करें।") == "hi"


# ---------------------------------------------------------------------------
# Placeholder-survival guardrail — mocked translator, no network call.
# ---------------------------------------------------------------------------


def test_bracket_placeholder_survives_translation():
    with patch("deep_translator.GoogleTranslator") as mock_cls:
        mock_cls.return_value.translate.return_value = "[DATE] mock translated text"
        settings.translation_enabled = True
        try:
            result = get_string("ta", "report", "summary_parts", "opener", default="FAIL")
        finally:
            settings.translation_enabled = True
        assert "[DATE]" in result


def test_dropped_bracket_placeholder_falls_back_to_english():
    with patch("deep_translator.GoogleTranslator") as mock_cls:
        # Translation drops [DATE] entirely -> guardrail must reject it.
        mock_cls.return_value.translate.return_value = "mock translated text with no date marker"
        settings.translation_enabled = True
        try:
            result = get_string("ta", "report", "summary_parts", "opener", default="FAIL")
        finally:
            settings.translation_enabled = True
        # Falls back to the real English string (contains [DATE]), not the
        # mocked/mangled translation.
        assert "[DATE]" in result
        assert "mock translated" not in result


def test_mangled_format_placeholder_falls_back_to_english():
    with patch("deep_translator.GoogleTranslator") as mock_cls:
        # Simulates GoogleTranslator translating the identifier inside {}
        # (observed real behavior: "{ask}" -> "{கேளும்படி}").
        mock_cls.return_value.translate.return_value = "மொழிபெயர்க்கப்பட்ட உரை {மங்கல்}."
        settings.translation_enabled = True
        try:
            result = get_string("ta", "report", "summary_parts", "asked", default="FAIL")
        finally:
            settings.translation_enabled = True
        # Falls back to the real English string, which contains the intact
        # {ask} placeholder — not the mangled {மங்கல்} from the mock.
        assert "{ask}" in result
        assert "{மங்கல்}" not in result


# ---------------------------------------------------------------------------
# TRANSLATION_ENABLED=False — no network call, ever.
# ---------------------------------------------------------------------------


def test_translation_disabled_returns_english_without_network_call():
    settings.translation_enabled = False
    try:
        with patch("deep_translator.GoogleTranslator") as mock_cls:
            result = get_string("ta", "fallback_templates", "kyc_bank", "explanation", default="FAIL")
            mock_cls.assert_not_called()
    finally:
        settings.translation_enabled = True
    assert result != "FAIL"
    assert "KYC" in result  # the real English fallback_templates.kyc_bank.explanation


def test_translation_disabled_never_raises_for_any_new_language():
    settings.translation_enabled = False
    try:
        for lang in ("ta", "kn", "ml", "bn", "mr", "gu", "pa"):
            result = get_string(lang, "whatsapp", "strings", "brand", default="FAIL")
            assert result == "Kavach"
    finally:
        settings.translation_enabled = True
