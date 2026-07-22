import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from main import app
from services import classifier as classifier_module
from services import llm as llm_module
from services.llm import LLMUnavailable
from services.rules import SCAM_TAXONOMY, SIGNALS

client = TestClient(app)


VERDICT_FIELDS = [
    "scam_type",
    "risk",
    "confidence",
    "decision_source",
    "fallback_used",
    "signals",
    "matched_patterns",
    "artifacts",
    "explanation",
    "recommended_action",
    "report",
    "detected_language",
]


def _assert_valid_verdict(body: dict) -> None:
    for field in VERDICT_FIELDS:
        assert field in body, f"missing field: {field}"
    assert body["scam_type"] in SCAM_TAXONOMY
    assert 0 <= body["risk"] <= 100
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["detected_language"] in ("en", "hi", "te")
    assert isinstance(body["signals"], list)
    for s in body["signals"]:
        assert s in SIGNALS
    assert isinstance(body["artifacts"], dict)
    assert "urls" in body["artifacts"] and "phones" in body["artifacts"]
    assert "channels" in body["report"]


# ---------------------------------------------------------------------------
# Force the LLM path off in these tests so they run without a real API key.
# Each test that wants a specific LLM output monkeypatches accordingly.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _force_llm_unavailable(monkeypatch):
    # Accept the optional `grounding=` kwarg the RAG-enabled classifier now passes.
    def _raise(_text: str, grounding: str = ""):
        raise LLMUnavailable("mocked: llm disabled in tests")

    monkeypatch.setattr(llm_module, "analyze_message", _raise)
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _raise)
    yield


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_analyze_returns_valid_verdict_shape():
    r = client.post("/analyze", json={"text": "hello"})
    assert r.status_code == 200
    _assert_valid_verdict(r.json())


def test_digital_arrest_english_high_risk():
    text = (
        "This is CBI. A case has been filed against you. You are under digital "
        "arrest. Stay on this Skype call and do not disconnect. Transfer "
        "verification funds immediately or a warrant will be issued."
    )
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    assert body["scam_type"] == "digital_arrest"
    assert body["risk"] >= 60
    assert body["fallback_used"] is True
    # RAG may promote to "rules_fallback+rag" when it attaches citations.
    assert body["decision_source"] in ("rules_fallback", "rules_fallback+rag")


def test_legit_bank_otp_is_not_flagged_high():
    text = "Your HDFC Bank OTP is 482913. Valid for 5 minutes. Do not share with anyone."
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    # Should NOT be classified as a scam type at high risk.
    assert body["risk"] < 60
    assert body["scam_type"] in ("likely_safe", "other", "credential_request", "kyc_bank")


def test_hindi_scam_detected_as_hindi():
    text = "आपके खाते बंद हो जाएगा। तुरंत KYC पूरा करें और OTP साझा करें।"
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    assert body["detected_language"] == "hi"
    assert body["explanation"], "explanation must be non-empty"


def test_telugu_scam_detected_as_telugu():
    text = "మీ ఖాతా బ్లాక్ అవుతుంది. వెంటనే KYC పూర్తి చేయండి, OTP పంపండి."
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    assert body["detected_language"] == "te"
    assert body["explanation"], "explanation must be non-empty"


def test_fallback_used_when_llm_raises():
    # The autouse fixture forces LLMUnavailable already.
    text = "You are under digital arrest, pay now to avoid a warrant."
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    assert body["fallback_used"] is True
    assert body["decision_source"] in ("rules_fallback", "rules_fallback+rag")
    assert body["confidence"] <= 0.6


def test_fusion_path_when_llm_succeeds(monkeypatch):
    # Override the autouse mock: LLM "succeeds" with a canned response.
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "fear", "payment"],
            "explanation": "Classic digital arrest pattern.",
            "recommended_action": "Do not pay. Report to 1930.",
            "detected_language": "en",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = "CBI digital arrest. Transfer verification funds immediately."
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    assert body["fallback_used"] is False
    # RAG may promote decision_source to "rules+llm+rag" if it retrieves a hit.
    assert body["decision_source"] in ("rules+llm", "rules+llm+rag")
    assert body["scam_type"] == "digital_arrest"
    # Agreement between rules and LLM should push confidence high.
    assert body["confidence"] >= 0.8


# ---------------------------------------------------------------------------
# Phase C: RAG grounding + citations
# ---------------------------------------------------------------------------


def test_retrieval_hits_relevant_patterns_for_digital_arrest():
    from services.rag import retrieve

    text = (
        "This is CBI. A parcel in your name has narcotics. Stay on this "
        "Skype call, do not tell anyone, transfer for verification."
    )
    hits = retrieve(text, top_k=3)
    assert len(hits) >= 1, "expected at least one KB hit for a clear scam"
    # At least one should be digital_arrest category.
    assert any(h["category"] == "digital_arrest" for h in hits)
    # Every returned hit has the schema we promise.
    for h in hits:
        assert {"id", "category", "title", "similarity", "matched_indicators"} <= set(h)
        assert 0.0 <= h["similarity"] <= 1.0


def test_retrieval_returns_nothing_for_benign_hi_mom():
    from services.rag import retrieve

    # Deliberately generic message with no scam indicators.
    hits = retrieve("Hi mom, reached office safely. Will call after lunch.")
    assert hits == [], f"expected no hits for benign text; got {hits}"


def test_verdict_has_matched_patterns_for_digital_arrest(monkeypatch):
    # LLM confidently classifies as digital_arrest — RAG should attach citations.
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "fear", "payment"],
            "explanation": "Classic digital arrest pattern.",
            "recommended_action": "Do not pay. Report to 1930.",
            "detected_language": "en",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = (
        "This is CBI. A parcel in your name has illegal items. Stay on this "
        "video call, do not tell anyone, transfer Rs 2 lakh for verification."
    )
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    # matched_patterns must be non-empty and same-category.
    assert body["matched_patterns"], "expected matched_patterns to be populated"
    for m in body["matched_patterns"]:
        assert m["category"] == "digital_arrest"
        assert m["id"]
        assert m["title"]
        assert 0.0 <= m["similarity"] <= 1.0
    # Decision source is promoted.
    assert body["decision_source"] == "rules+llm+rag"


def test_regression_guard_legit_otp_stays_safe(monkeypatch):
    # Simulate the LLM correctly returning likely_safe with high confidence
    # for a legitimate OTP message. RAG's SAFE LOCK must prevent it from
    # flipping the decision or attaching phishing citations.
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "likely_safe",
            "risk": 10,
            "confidence": 0.95,
            "signals": [],
            "explanation": "Legitimate HDFC bank OTP delivery.",
            "recommended_action": "Do not share OTP with anyone.",
            "detected_language": "en",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = "Your HDFC Bank OTP is 483920. Do not share it with anyone. Valid for 10 minutes."
    r = client.post("/analyze", json={"text": text})
    assert r.status_code == 200
    body = r.json()
    _assert_valid_verdict(body)
    # Load-bearing assertions:
    assert body["scam_type"] == "likely_safe", "RAG must not flip a confident likely_safe"
    assert body["risk"] < 40, f"RAG must not push risk above threshold; got {body['risk']}"
    assert body["matched_patterns"] == [], (
        "RAG must not attach phishing citations to a confident likely_safe verdict"
    )
    # decision_source must NOT get the +rag suffix in the safe-locked case.
    assert body["decision_source"] == "rules+llm"


def test_rag_confidence_nudge_is_bounded(monkeypatch):
    # Even with several strong same-category hits, the nudge must not push
    # confidence beyond 0.10 above the pre-RAG value.
    from services import classifier as cm

    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.80,
            "signals": ["authority"],
            "explanation": "Digital arrest pattern.",
            "recommended_action": "Report to 1930.",
            "detected_language": "en",
        }

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm)

    text = (
        "CBI officer. Case filed against you. Warrant will be issued. Stay on "
        "Skype call, do not tell anyone, transfer verification account."
    )
    r = client.post("/analyze", json={"text": text})
    body = r.json()
    # After fusion (agreement -> +0.15) confidence is ~0.95 already; RAG can
    # push at most +0.10 further, capped by the 0.98 ceiling.
    assert body["confidence"] <= 0.98


# ---------------------------------------------------------------------------
# Phase D: Guided fraud reporting
# ---------------------------------------------------------------------------


def _assert_valid_report(rep: dict) -> None:
    for f in ("should_report", "urgency", "channels", "prefilled_summary",
              "evidence_checklist", "language"):
        assert f in rep, f"report missing field: {f}"
    assert rep["urgency"] in ("immediate", "standard", "none")
    assert isinstance(rep["channels"], list) and rep["channels"], "channels empty"
    for ch in rep["channels"]:
        assert {"name", "type", "value", "when"} <= set(ch)
    assert rep["language"] in ("en", "hi", "te")


def test_report_reportable_scam_english(monkeypatch):
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "fear", "payment"],
            "explanation": "Classic digital arrest pattern.",
            "recommended_action": "Do not pay. Report to 1930.",
            "detected_language": "en",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = (
        "This is CBI. A parcel in your name has illegal items. Stay on this "
        "video call, do not tell anyone, transfer Rs 2 lakh for verification."
    )
    r = client.post("/analyze", json={"text": text})
    body = r.json()
    _assert_valid_verdict(body)

    rep = body["report"]
    _assert_valid_report(rep)
    assert rep["should_report"] is True
    assert rep["urgency"] in ("immediate", "standard")
    # payment signal + risk 92 => "immediate"
    assert rep["urgency"] == "immediate"
    assert len(rep["channels"]) == 3
    # 1930 must be first for high-urgency scams.
    assert rep["channels"][0]["value"] == "1930"
    assert rep["prefilled_summary"], "prefilled_summary must be non-empty"
    assert rep["language"] == "en"
    assert rep["evidence_checklist"], "evidence_checklist must be non-empty"


def test_report_legit_otp_does_not_push_complaint(monkeypatch):
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "likely_safe",
            "risk": 10,
            "confidence": 0.95,
            "signals": [],
            "explanation": "Legitimate HDFC bank OTP.",
            "recommended_action": "Do not share OTP with anyone.",
            "detected_language": "en",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = "Your HDFC Bank OTP is 483920. Do not share it with anyone. Valid for 10 minutes."
    r = client.post("/analyze", json={"text": text})
    body = r.json()
    _assert_valid_verdict(body)

    rep = body["report"]
    _assert_valid_report(rep)
    assert rep["should_report"] is False
    assert rep["urgency"] == "none"
    assert rep["prefilled_summary"] == ""
    # 1930 must NOT be shown for a legit message.
    assert all(ch["value"] != "1930" for ch in rep["channels"])


def test_report_summary_is_hindi_for_hindi_scam(monkeypatch):
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 90,
            "confidence": 0.9,
            "signals": ["authority", "fear"],
            "explanation": "डिजिटल अरेस्ट पैटर्न।",
            "recommended_action": "1930 पर कॉल करें।",
            "detected_language": "hi",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = (
        "मैं CBI से बोल रहा हूं। आपके नाम पर मुकदमा दर्ज है। तुरंत Skype कॉल पर "
        "आएं, किसी को मत बताना, अन्यथा गिरफ्तार वारंट जारी होगा।"
    )
    r = client.post("/analyze", json={"text": text})
    body = r.json()
    rep = body["report"]
    _assert_valid_report(rep)
    assert rep["language"] == "hi"
    # Devanagari must appear in the summary.
    assert re.search(r"[ऀ-ॿ]", rep["prefilled_summary"]), (
        f"expected Devanagari text in prefilled_summary; got {rep['prefilled_summary']!r}"
    )


def test_report_summary_is_telugu_for_telugu_scam(monkeypatch):
    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "kyc_bank",
            "risk": 85,
            "confidence": 0.9,
            "signals": ["fear", "urgency", "credential_request"],
            "explanation": "KYC మోసం.",
            "recommended_action": "1930 కి కాల్ చేయండి.",
            "detected_language": "te",
        }

    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _fake_llm)

    text = "మీ SBI ఖాతా బ్లాక్ అవుతుంది. KYC అప్డేట్ కోసం OTP వెంటనే షేర్ చేయండి."
    r = client.post("/analyze", json={"text": text})
    body = r.json()
    rep = body["report"]
    _assert_valid_report(rep)
    assert rep["language"] == "te"
    assert re.search(r"[ఀ-౿]", rep["prefilled_summary"]), (
        f"expected Telugu text in prefilled_summary; got {rep['prefilled_summary']!r}"
    )


def test_report_does_not_perturb_decision(monkeypatch):
    """Regression: adding the report step must not change any decision field.

    Calls analyze() directly, snapshots decision fields, temporarily disables
    the report step, calls again, and compares byte-for-byte.
    """
    from services import classifier as cm
    from services import report as rp

    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "fear", "payment"],
            "explanation": "Digital arrest pattern.",
            "recommended_action": "Report to 1930.",
            "detected_language": "en",
        }

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm)

    text = (
        "This is CBI. A parcel in your name has illegal items. Stay on video "
        "call, do not tell anyone, transfer for verification."
    )

    # Run WITH report step.
    v_with = cm.analyze(text)

    # Neutralize the report step and re-run.
    monkeypatch.setattr(
        rp, "build_report", lambda verdict, txt: {"channels": [], "prefilled_summary": ""}
    )
    # classifier imported report at module-load, patch that binding too.
    monkeypatch.setattr(
        cm.report_service, "build_report",
        lambda verdict, txt: {"channels": [], "prefilled_summary": ""},
    )
    v_without = cm.analyze(text)

    for field in ("scam_type", "risk", "confidence", "decision_source",
                  "fallback_used", "signals", "matched_patterns"):
        assert v_with[field] == v_without[field], (
            f"report step perturbed field {field!r}: "
            f"{v_with[field]!r} vs {v_without[field]!r}"
        )
