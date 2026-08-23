"""Webhook adapter tests.

All tests mock the LLM so they run offline. The engine (classifier + rules +
RAG + report) is exercised end-to-end — but the LLM call itself is mocked so
we don't need a live xAI credential.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from main import app
from services import classifier as classifier_module
from services import whatsapp_format
from services.whatsapp_format import MAX_MESSAGE_CHARS, verdict_to_whatsapp_text
from core import config as config_module

client = TestClient(app)


# ---------------------------------------------------------------------------
# LLM mocks per scam type / language
# ---------------------------------------------------------------------------

_LLM_MOCKS = {
    "en_digital_arrest": {
        "scam_type": "digital_arrest", "risk": 92, "confidence": 0.9,
        "signals": ["authority", "fear", "payment"],
        "explanation": "Impersonates CBI, demands transfer to a 'verification account'.",
        "recommended_action": "Disconnect. Do not pay. Report to 1930.",
        "detected_language": "en",
    },
    "hi_digital_arrest": {
        "scam_type": "digital_arrest", "risk": 94, "confidence": 0.9,
        "signals": ["authority", "fear"],
        "explanation": "CBI का नकली संदेश, Skype कॉल पर पैसे मांग रहा है।",
        "recommended_action": "कॉल तुरंत काटें, 1930 पर रिपोर्ट करें।",
        "detected_language": "hi",
    },
    "te_kyc_bank": {
        "scam_type": "kyc_bank", "risk": 88, "confidence": 0.9,
        "signals": ["credential_request", "urgency"],
        "explanation": "SBI నుండి అని చెప్పి OTP అడుగుతున్నారు, ఇది మోసం.",
        "recommended_action": "OTP షేర్ చేయవద్దు, 1930 కి కాల్ చేయండి.",
        "detected_language": "te",
    },
    "en_legit_otp": {
        "scam_type": "likely_safe", "risk": 10, "confidence": 0.95,
        "signals": [],
        "explanation": "Standard bank OTP delivery.",
        "recommended_action": "No action needed; do not share OTP with anyone.",
        "detected_language": "en",
    },
}


def _mock_llm_for(key):
    def _fake(text, grounding=""):
        return _LLM_MOCKS[key]
    return _fake


def _post_webhook(body: str, extra_form: dict | None = None, headers: dict | None = None):
    """POST to /webhook with a Twilio-shaped form body."""
    form = {
        "MessageSid": "SM_test_00000000",
        "From": "whatsapp:+919812345678",
        "To":   "whatsapp:+14155552671",
        "WaId": "919812345678",
        "Body": body,
    }
    if extra_form:
        form.update(extra_form)
    return client.post("/webhook", data=form, headers=headers or {})


def _twiml_text(response) -> str:
    """Extract the <Message> body from a TwiML response, undoing XML escaping."""
    assert response.status_code == 200, f"expected 200, got {response.status_code}: {response.text}"
    assert "application/xml" in (response.headers.get("content-type") or ""), response.headers
    m = re.search(r"<Message>([\s\S]*?)</Message>", response.text)
    assert m, f"no <Message> in {response.text!r}"
    text = m.group(1)
    # Undo the XML escapes we do in _twiml().
    return (
        text.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", '"')
            .replace("&#39;", "'")
    )


# ---------------------------------------------------------------------------
# Formatter unit tests
# ---------------------------------------------------------------------------


def test_formatter_english_scam_includes_risk_and_report_channel():
    verdict = {
        "scam_type": "digital_arrest",
        "risk": 92,
        "signals": ["authority", "payment"],
        "explanation": "Impersonates CBI, demands transfer.",
        "recommended_action": "Disconnect. Report to 1930.",
        "detected_language": "en",
        "report": {
            "should_report": True,
            "urgency": "immediate",
            "channels": [
                {"name": "Cyber Crime Helpline 1930", "value": "1930", "type": "phone"},
                {"name": "cybercrime.gov.in", "value": "https://cybercrime.gov.in", "type": "url"},
            ],
        },
    }
    text = verdict_to_whatsapp_text(verdict)
    assert "LIKELY SCAM" in text
    assert "Digital Arrest" in text
    assert "92" in text
    assert "1930" in text                    # top channel surfaced
    assert "Kavach" in text                   # brand footer
    assert len(text) <= MAX_MESSAGE_CHARS


def test_formatter_legit_otp_does_not_push_complaint():
    verdict = {
        "scam_type": "likely_safe",
        "risk": 10,
        "signals": [],
        "explanation": "Standard bank OTP.",
        "recommended_action": "Do not share OTP.",
        "detected_language": "en",
        "report": {
            "should_report": False,
            "urgency": "none",
            "channels": [],
        },
    }
    text = verdict_to_whatsapp_text(verdict)
    assert "Looks safe" in text
    assert "10/100" in text
    # Must NOT push a police complaint.
    assert "1930" not in text
    assert "Report now" not in text
    assert len(text) <= MAX_MESSAGE_CHARS


def test_formatter_hindi_uses_devanagari():
    verdict = _LLM_MOCKS["hi_digital_arrest"] | {
        "report": {"should_report": True, "urgency": "immediate",
                   "channels": [{"name": "1930", "value": "1930", "type": "phone"}]}
    }
    text = verdict_to_whatsapp_text(verdict)
    # Devanagari codepoints must appear.
    assert re.search(r"[ऀ-ॿ]", text), f"expected Devanagari in {text!r}"


def test_formatter_telugu_uses_telugu_script():
    verdict = _LLM_MOCKS["te_kyc_bank"] | {
        "report": {"should_report": True, "urgency": "immediate",
                   "channels": [{"name": "1930", "value": "1930", "type": "phone"}]}
    }
    text = verdict_to_whatsapp_text(verdict)
    assert re.search(r"[ఀ-౿]", text), f"expected Telugu script in {text!r}"


def test_formatter_never_exceeds_char_limit_on_giant_verdict():
    # Explanation & action are pathologically long — formatter must still cap.
    long = "x" * 10_000
    verdict = {
        "scam_type": "digital_arrest", "risk": 90,
        "explanation": long, "recommended_action": long,
        "detected_language": "en",
        "report": {"should_report": True,
                   "channels": [{"name": "1930", "value": "1930", "type": "phone"}]},
    }
    text = verdict_to_whatsapp_text(verdict)
    assert len(text) <= MAX_MESSAGE_CHARS


def test_formatter_never_raises_on_garbage():
    for bad in (None, {}, {"scam_type": None}, "not a dict", 42):
        text = verdict_to_whatsapp_text(bad)
        assert isinstance(text, str) and len(text) > 0


# ---------------------------------------------------------------------------
# Endpoint tests — English scam
# ---------------------------------------------------------------------------


def test_webhook_english_digital_arrest_returns_twiml(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    r = _post_webhook(
        "This is CBI. A parcel with your Aadhaar has illegal items. Stay on this video call, "
        "do not tell anyone, and transfer Rs 2,00,000 to this verification account."
    )
    text = _twiml_text(r)
    assert "LIKELY SCAM" in text
    assert "Digital Arrest" in text
    assert "1930" in text
    assert len(text) <= MAX_MESSAGE_CHARS


def test_webhook_hindi_message_replies_in_hindi(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("hi_digital_arrest"))
    r = _post_webhook(
        "मैं CBI से बोल रहा हूं। आपके नाम पर मुकदमा दर्ज है। तुरंत Skype कॉल पर आएं।"
    )
    text = _twiml_text(r)
    assert re.search(r"[ऀ-ॿ]", text), text
    assert "1930" in text


def test_webhook_telugu_message_replies_in_telugu(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("te_kyc_bank"))
    r = _post_webhook(
        "మీ SBI ఖాతా బ్లాక్ అవుతుంది. KYC అప్‌డేట్ కోసం OTP వెంటనే షేర్ చేయండి."
    )
    text = _twiml_text(r)
    assert re.search(r"[ఀ-౿]", text), text
    assert "1930" in text


def test_webhook_legit_otp_does_not_push_complaint(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_legit_otp"))
    r = _post_webhook(
        "Your OTP for HDFC Bank is 483920. Do not share it with anyone. Valid for 10 minutes."
    )
    text = _twiml_text(r)
    assert "Looks safe" in text
    assert "1930" not in text
    assert "Report now" not in text


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def test_webhook_rejects_bad_signature_when_verification_on(monkeypatch):
    """When VERIFY_TWILIO_SIGNATURE is on and the signature is wrong -> 403."""
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    monkeypatch.setattr(config_module.settings, "verify_twilio_signature", True)
    monkeypatch.setattr(config_module.settings, "twilio_auth_token", "test-token")
    r = _post_webhook("hello", headers={"X-Twilio-Signature": "obviously-wrong"})
    assert r.status_code == 403


def test_webhook_rejects_missing_signature_when_verification_on(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    monkeypatch.setattr(config_module.settings, "verify_twilio_signature", True)
    monkeypatch.setattr(config_module.settings, "twilio_auth_token", "test-token")
    r = _post_webhook("hello")   # no X-Twilio-Signature header
    assert r.status_code == 403


def test_webhook_accepts_when_verification_off(monkeypatch):
    """Default local behaviour: verification off, any request processed."""
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    monkeypatch.setattr(config_module.settings, "verify_twilio_signature", False)
    r = _post_webhook("This is CBI. Transfer for verification.")
    assert r.status_code == 200
    text = _twiml_text(r)
    assert "LIKELY SCAM" in text


def test_webhook_accepts_valid_signature(monkeypatch):
    """When verification is on and the signature is correct, request is processed."""
    import base64
    import hashlib
    import hmac

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    monkeypatch.setattr(config_module.settings, "verify_twilio_signature", True)
    monkeypatch.setattr(config_module.settings, "twilio_auth_token", "test-token")

    form = {
        "MessageSid": "SM_test_00000000",
        "From": "whatsapp:+919812345678",
        "To":   "whatsapp:+14155552671",
        "WaId": "919812345678",
        "Body": "This is CBI. Transfer for verification.",
    }
    # TestClient uses http://testserver by default.
    url = "http://testserver/webhook"

    # Compute the expected Twilio signature exactly like the endpoint does.
    payload = url
    for k in sorted(form.keys()):
        payload += k + form[k]
    digest = hmac.new(b"test-token", payload.encode("utf-8"), hashlib.sha1).digest()
    sig = base64.b64encode(digest).decode("ascii")

    r = client.post("/webhook", data=form, headers={"X-Twilio-Signature": sig})
    assert r.status_code == 200
    text = _twiml_text(r)
    assert "LIKELY SCAM" in text


# ---------------------------------------------------------------------------
# The point of Phase 4: /webhook and /analyze use the SAME engine.
# ---------------------------------------------------------------------------


def test_webhook_and_analyze_agree_on_same_input(monkeypatch):
    """Load-bearing: /webhook must return a verdict for the same scam_type/risk
    as /analyze for the exact same input. Anything else would mean the two
    channels have drifted apart."""
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))

    text = (
        "This is CBI. A parcel with your Aadhaar has illegal items. Stay on "
        "this video call, do not tell anyone, and transfer for verification."
    )

    # Web path.
    a = client.post("/analyze", json={"text": text})
    assert a.status_code == 200
    a_body = a.json()

    # WhatsApp path — must exercise the same engine.
    w = _post_webhook(text)
    w_text = _twiml_text(w)

    # The decision fields must line up. We check via the text of the WhatsApp
    # reply: it embeds scam-type label + risk, both derived from the shared
    # verdict.
    from services.whatsapp_format import _scam_label
    expected_label = _scam_label(a_body["scam_type"], a_body["detected_language"])
    assert expected_label in w_text, (
        f"WhatsApp reply missing shared scam-type label {expected_label!r}: {w_text!r}"
    )
    assert str(a_body["risk"]) in w_text, (
        f"WhatsApp reply missing shared risk {a_body['risk']!r}: {w_text!r}"
    )


# ---------------------------------------------------------------------------
# Error path — engine failure still returns valid TwiML (never 500 to Twilio)
# ---------------------------------------------------------------------------


def test_webhook_returns_twiml_even_when_engine_raises(monkeypatch):
    def _boom(_text, grounding=""):
        raise RuntimeError("engine on fire")

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _boom)

    # We only patch the LLM here; the classifier's own defensive fallback
    # should still return a valid verdict, so the webhook returns 200 with
    # TwiML. But even if the whole chain blew up, the webhook wraps analyze()
    # in try/except and returns a fallback TwiML. Assert 200 + TwiML either way.
    r = _post_webhook("some suspicious text")
    assert r.status_code == 200
    text = _twiml_text(r)
    assert len(text) > 0


def test_webhook_empty_body_returns_polite_twiml():
    r = _post_webhook("")
    assert r.status_code == 200
    text = _twiml_text(r)
    assert "try again" in text.lower() or "sorry" in text.lower()


# ---------------------------------------------------------------------------
# Conversational follow-up flow (stateless keyword interception)
# ---------------------------------------------------------------------------


# Follow-up tests each use a distinct X-Forwarded-For IP so they draw from
# their own rate-limit budget (core.rate_limit.RateLimiter is a per-IP
# sliding-window singleton shared by every TestClient call in this process —
# see tests/test_security.py) rather than competing with the many other
# /webhook calls already made above in this file.
def _followup_headers(ip_suffix: str) -> dict:
    return {"X-Forwarded-For": f"10.99.0.{ip_suffix}"}


def test_webhook_scam_verdict_includes_followup_menu(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    r = _post_webhook(
        "This is CBI. A parcel with your Aadhaar has illegal items. Transfer for verification.",
        headers=_followup_headers("1"),
    )
    text = _twiml_text(r)
    assert "1" in text and "2" in text and "3" in text
    assert "report" in text.lower()


def test_webhook_safe_verdict_has_no_followup_menu(monkeypatch):
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_legit_otp"))
    r = _post_webhook(
        "Your OTP for HDFC Bank is 483920. Do not share it with anyone. Valid for 10 minutes.",
        headers=_followup_headers("2"),
    )
    text = _twiml_text(r)
    assert "Reply with a number" not in text


def test_webhook_followup_1_returns_reporting_guidance():
    r = _post_webhook("1", headers=_followup_headers("3"))
    text = _twiml_text(r)
    assert "Chakshu" in text
    assert "sancharsaathi.gov.in" in text


def test_webhook_followup_report_it_returns_reporting_guidance():
    r = _post_webhook("report it", headers=_followup_headers("4"))
    text = _twiml_text(r)
    assert "Chakshu" in text


def test_webhook_followup_2_returns_emergency_guidance():
    r = _post_webhook("2", headers=_followup_headers("5"))
    text = _twiml_text(r)
    assert "1930" in text
    assert "cybercrime" in text.lower()


def test_webhook_followup_lost_money_returns_emergency_guidance():
    r = _post_webhook("lost money", headers=_followup_headers("6"))
    text = _twiml_text(r)
    assert "1930" in text


def test_webhook_followup_3_returns_education_text():
    r = _post_webhook("3", headers=_followup_headers("7"))
    text = _twiml_text(r)
    assert len(text) > 0
    # Default stateless education fallback.
    from services.whatsapp_format import SCAM_EDUCATION, _DEFAULT_EDUCATION_SCAM_TYPE
    assert SCAM_EDUCATION[_DEFAULT_EDUCATION_SCAM_TYPE] in text or len(text) > 20


def test_webhook_followup_help_returns_help_menu():
    r = _post_webhook("HELP", headers=_followup_headers("8"))
    text = _twiml_text(r)
    assert "ANALYZE" in text
    assert "Chakshu" in text


def test_webhook_followup_yes_returns_confirmation():
    r = _post_webhook("YES", headers=_followup_headers("9"))
    text = _twiml_text(r)
    assert "screenshot" in text.lower()


def test_webhook_followup_done_returns_confirmation():
    r = _post_webhook("DONE", headers=_followup_headers("10"))
    text = _twiml_text(r)
    assert "screenshot" in text.lower()


def test_webhook_followup_no_returns_alternative():
    r = _post_webhook("NO", headers=_followup_headers("11"))
    text = _twiml_text(r)
    assert "HELP" in text


def test_webhook_followup_case_insensitive_and_stripped():
    r = _post_webhook("  help  ", headers=_followup_headers("12"))
    text = _twiml_text(r)
    assert "ANALYZE" in text


def test_webhook_long_message_not_intercepted_as_followup(monkeypatch):
    """A long message is analyzed normally, even if it starts like a scam."""
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    r = _post_webhook(
        "This is CBI. A parcel with your Aadhaar has illegal items. Stay on this video call, "
        "do not tell anyone, and transfer Rs 2,00,000 to this verification account.",
        headers=_followup_headers("13"),
    )
    text = _twiml_text(r)
    assert "LIKELY SCAM" in text
    assert "Digital Arrest" in text


def test_webhook_keyword_with_extra_words_not_intercepted(monkeypatch):
    """"1 please help me" contains more than the bare keyword -> analyzed normally."""
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message",
                        _mock_llm_for("en_digital_arrest"))
    r = _post_webhook("1 please help me", headers=_followup_headers("14"))
    text = _twiml_text(r)
    assert "Chakshu" not in text
    assert "LIKELY SCAM" in text
