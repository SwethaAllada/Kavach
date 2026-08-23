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

# "phishing_url" is deliberately NOT part of services.rules.SIGNALS (see
# classifier._apply_url_reputation's docstring) — SIGNALS is interpolated
# into llm.py's prompt/output-allowlist, and this signal must only ever
# come from a deterministic PhishTank hit, never LLM guesswork. Verdicts
# validate against this superset instead.
_ALL_KNOWN_SIGNALS = set(SIGNALS) | {"phishing_url"}


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
    "case_id",
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
        assert s in _ALL_KNOWN_SIGNALS
    assert isinstance(body["artifacts"], dict)
    assert "urls" in body["artifacts"] and "phones" in body["artifacts"]
    assert "channels" in body["report"]
    assert re.fullmatch(r"KAV-\d{8}-[A-Z0-9]{4}", body["case_id"]), (
        f"case_id does not match KAV-YYYYMMDD-XXXX: {body['case_id']!r}"
    )


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


# ---------------------------------------------------------------------------
# Phase 3: anonymized telemetry + Trends
# ---------------------------------------------------------------------------


def test_to_anonymized_record_strips_everything_but_whitelist():
    """The anonymized record must contain ONLY the whitelisted keys, even when
    the input verdict has message text, phrases, and URLs on it."""
    from core.privacy import to_anonymized_record, anonymized_fields

    verdict = {
        "scam_type": "digital_arrest",
        "risk": 92,
        "confidence": 0.95,
        "decision_source": "rules+llm+rag",
        "fallback_used": False,
        "signals": ["authority", "payment"],
        "matched_patterns": [
            {
                "id": "DA-01",
                "title": "Courier parcel → CBI/Customs digital arrest",
                # These indicators echo user phrasing and MUST NOT be stored:
                "matched_indicators": ["parcel with your aadhaar", "cbi"],
            }
        ],
        "artifacts": {
            "urls": ["https://sbi-kyc-verify.co.in"],
            "phones": ["+919812345678"],
        },
        "explanation": "This is user-supplied text that MUST NOT be stored.",
        "recommended_action": "another user-language string",
        "detected_language": "en",
        "report": {
            "should_report": True,
            "urgency": "immediate",
            # This is derived from the user's message and MUST NOT be stored:
            "prefilled_summary": "On [DATE], I received a message from CBI...",
            "channels": [{"name": "1930", "value": "1930"}],
        },
    }

    record = to_anonymized_record(verdict)

    # (1) Exactly and only the whitelist.
    assert set(record.keys()) == anonymized_fields()

    # (2) The whitelisted values are the expected shape.
    assert record["scam_type"] == "digital_arrest"
    assert record["risk_bucket"] == "high"        # 92 -> high
    assert record["detected_language"] == "en"
    assert record["decision_source"] == "rules+llm+rag"
    assert record["fallback_used"] is False

    # (3) Load-bearing: no user-supplied text or phrase can appear anywhere.
    serialized = repr(record)
    banned_snippets = [
        "aadhaar",       # matched_indicator
        "cbi",           # matched_indicator (lowercase form we stored)
        "sbi-kyc",       # url
        "9812345678",    # phone
        "user-supplied", # explanation
        "user-language", # recommended_action
        "[DATE]",        # prefilled_summary
        "channels",      # from report
        "urgency",       # from report
    ]
    for snippet in banned_snippets:
        assert snippet.lower() not in serialized.lower(), (
            f"anonymized record leaked user data (found {snippet!r} in {serialized!r})"
        )

    # (4) Raw risk score MUST NOT be present — only the bucket.
    assert "risk" not in record
    assert 92 not in record.values()


def test_to_anonymized_record_bucket_boundaries():
    from core.privacy import to_anonymized_record
    for risk, expected in [(0, "low"), (39, "low"), (40, "medium"), (69, "medium"),
                           (70, "high"), (99, "high"), (100, "high")]:
        rec = to_anonymized_record({"risk": risk, "scam_type": "other"})
        assert rec["risk_bucket"] == expected, f"risk={risk} -> {rec['risk_bucket']}"


def test_to_anonymized_record_never_raises_on_bad_input():
    from core.privacy import to_anonymized_record, anonymized_fields
    # None, bad types, missing keys — must still return a whitelist dict.
    for bad in (None, [], "string", 42, {"risk": "not-a-number"}):
        rec = to_anonymized_record(bad)
        assert set(rec.keys()) == anonymized_fields()


def test_analyze_still_returns_valid_verdict_when_telemetry_raises(monkeypatch):
    """Load-bearing: /analyze must be unaffected by telemetry failures."""
    from services import classifier as cm

    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "payment"],
            "explanation": "Classic digital arrest pattern.",
            "recommended_action": "Report to 1930.",
            "detected_language": "en",
        }

    def _boom(_record):
        raise RuntimeError("supabase is on fire")

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm)
    monkeypatch.setattr(cm.store_service, "log_signal", _boom)

    text = (
        "This is CBI. A parcel in your name has illegal items. Stay on video "
        "call, do not tell anyone, transfer for verification."
    )
    verdict = cm.analyze(text)
    _assert_valid_verdict(verdict)
    assert verdict["scam_type"] == "digital_arrest"


def test_telemetry_does_not_perturb_decision(monkeypatch):
    """Byte-identity: decision fields must be identical whether telemetry is
    on (log_signal succeeds) or off (log_signal is a no-op).
    """
    from services import classifier as cm

    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "payment"],
            "explanation": "Digital arrest pattern.",
            "recommended_action": "Report to 1930.",
            "detected_language": "en",
        }

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm)

    text = (
        "This is CBI. A parcel in your name has illegal items. Stay on video "
        "call, do not tell anyone, transfer for verification."
    )

    # Telemetry ON (records into a list) vs OFF (no-op).
    captured = []
    monkeypatch.setattr(cm.store_service, "log_signal", lambda r: captured.append(r))
    v_on = cm.analyze(text)
    assert len(captured) == 1
    assert set(captured[0].keys()) == cm.privacy_module.anonymized_fields()

    monkeypatch.setattr(cm.store_service, "log_signal", lambda r: None)
    v_off = cm.analyze(text)

    for field in ("scam_type", "risk", "confidence", "decision_source",
                  "fallback_used", "signals", "matched_patterns", "report"):
        assert v_on[field] == v_off[field], (
            f"telemetry perturbed field {field!r}: {v_on[field]!r} vs {v_off[field]!r}"
        )


def test_get_trends_empty_shape(monkeypatch):
    """When store isn't configured / no rows, get_trends returns a valid empty shape."""
    from services import store

    monkeypatch.setattr(store, "_is_configured", lambda: False)
    out = store.get_trends()
    assert out["status"] == "unavailable"
    assert out["total_count"] == 0
    assert out["by_scam_type"] == {}
    assert out["by_risk_bucket"] == {"low": 0, "medium": 0, "high": 0}
    assert out["by_language"] == {}
    assert out["last_7_days"] == []


def test_get_trends_aggregation_on_sample_rows():
    """aggregate() computes the expected counts from a list of anonymized rows."""
    from datetime import datetime, timezone
    from services.store import aggregate

    today_iso = datetime.now(timezone.utc).isoformat()
    rows = [
        {"scam_type": "digital_arrest", "risk_bucket": "high",   "detected_language": "en", "decision_source": "rules+llm+rag", "fallback_used": False, "created_at": today_iso},
        {"scam_type": "digital_arrest", "risk_bucket": "high",   "detected_language": "hi", "decision_source": "rules+llm+rag", "fallback_used": False, "created_at": today_iso},
        {"scam_type": "kyc_bank",       "risk_bucket": "high",   "detected_language": "te", "decision_source": "rules+llm+rag", "fallback_used": False, "created_at": today_iso},
        {"scam_type": "likely_safe",    "risk_bucket": "low",    "detected_language": "en", "decision_source": "rules+llm",     "fallback_used": False, "created_at": today_iso},
        {"scam_type": "other",          "risk_bucket": "medium", "detected_language": "en", "decision_source": "rules_fallback","fallback_used": True,  "created_at": today_iso},
    ]
    out = aggregate(rows)
    assert out["status"] == "ok"
    assert out["total_count"] == 5
    assert out["by_scam_type"]["digital_arrest"] == 2
    assert out["by_scam_type"]["kyc_bank"] == 1
    assert out["by_risk_bucket"] == {"low": 1, "medium": 1, "high": 3}
    assert out["by_language"] == {"en": 3, "hi": 1, "te": 1}
    assert out["by_decision_source"]["rules+llm+rag"] == 3
    assert out["fallback_used_count"] == 1
    assert len(out["last_7_days"]) == 7
    # The five sample rows all land in today's bucket.
    assert out["last_7_days"][-1]["count"] == 5


def test_get_trends_route_returns_valid_shape_when_store_down(monkeypatch):
    """GET /trends never 500s even if the underlying store is unreachable."""
    from services import store as store_module
    # Simulate the store being unconfigured -> get_trends returns 'unavailable'.
    monkeypatch.setattr(store_module, "_is_configured", lambda: False)
    r = client.get("/trends")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "unavailable"
    assert body["total_count"] == 0
    assert "by_scam_type" in body
    assert "last_7_days" in body


# ---------------------------------------------------------------------------
# Case ID + audit trail (legal admissibility)
# ---------------------------------------------------------------------------


def test_analyze_returns_case_id_matching_format():
    r = client.post("/analyze", json={"text": "hello"})
    assert r.status_code == 200
    body = r.json()
    assert re.fullmatch(r"KAV-\d{8}-[A-Z0-9]{4}", body["case_id"])


def test_two_consecutive_analyze_calls_return_different_case_ids():
    r1 = client.post("/analyze", json={"text": "hello"})
    r2 = client.post("/analyze", json={"text": "hello"})
    assert r1.json()["case_id"] != r2.json()["case_id"]


def test_input_hash_is_valid_sha256_hex(monkeypatch):
    """input_hash written to the audit record is a 64-char hex SHA-256 digest,
    matching hashlib.sha256(text.encode()).hexdigest()."""
    import hashlib
    from services import classifier as cm

    captured = []
    monkeypatch.setattr(cm.store_service, "log_audit_record", lambda r: captured.append(r))

    text = "This is CBI. Transfer for verification."
    cm.analyze(text)

    assert len(captured) == 1
    input_hash = captured[0]["input_hash"]
    assert isinstance(input_hash, str)
    assert len(input_hash) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", input_hash)
    assert input_hash == hashlib.sha256(text.encode()).hexdigest()


def test_audit_log_write_failure_does_not_affect_verdict(monkeypatch):
    """Load-bearing: /analyze must be unaffected by audit-log write failures,
    same fire-and-forget discipline as telemetry."""
    from services import classifier as cm

    def _fake_llm(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest",
            "risk": 92,
            "confidence": 0.9,
            "signals": ["authority", "payment"],
            "explanation": "Classic digital arrest pattern.",
            "recommended_action": "Report to 1930.",
            "detected_language": "en",
        }

    def _boom(_record):
        raise RuntimeError("audit store is on fire")

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm)
    monkeypatch.setattr(cm.store_service, "log_audit_record", _boom)

    text = "This is CBI. Transfer for verification."
    verdict = cm.analyze(text)
    _assert_valid_verdict(verdict)
    assert verdict["scam_type"] == "digital_arrest"


def test_audit_record_has_expected_shape(monkeypatch):
    from services import classifier as cm

    captured = []
    monkeypatch.setattr(cm.store_service, "log_audit_record", lambda r: captured.append(r))

    cm.analyze("This is CBI. Transfer for verification.")

    assert len(captured) == 1
    record = captured[0]
    for field in (
        "case_id", "scam_type", "risk_bucket", "confidence_bucket",
        "decision_source", "detected_language", "matched_pattern_ids",
        "fallback_used", "input_hash",
    ):
        assert field in record, f"audit record missing field: {field}"
    assert record["confidence_bucket"] in ("high", "medium", "low")


def test_confidence_bucket_boundaries():
    from services.classifier import _confidence_bucket
    assert _confidence_bucket(0.95) == "high"
    assert _confidence_bucket(0.81) == "high"
    assert _confidence_bucket(0.80) == "medium"
    assert _confidence_bucket(0.5) == "medium"
    assert _confidence_bucket(0.49) == "low"
    assert _confidence_bucket(0.0) == "low"
    assert _confidence_bucket(None) == "low"


def test_get_case_returns_audit_record_when_found(monkeypatch):
    """GET /case/{case_id} returns the audit_log row from a mocked Supabase."""
    from services import store as store_module

    fake_row = {
        "case_id": "KAV-20260824-A7K2",
        "scam_type": "digital_arrest",
        "risk_bucket": "high",
        "confidence_bucket": "high",
        "decision_source": "rules+llm",
        "detected_language": "en",
        "matched_pattern_ids": "DA-01,DA-03",
        "fallback_used": False,
        "input_hash": "a" * 64,
        "created_at": "2026-08-24T00:07:00+00:00",
    }
    monkeypatch.setattr(store_module, "get_audit_record", lambda case_id: fake_row)

    r = client.get("/case/KAV-20260824-A7K2")
    assert r.status_code == 200
    body = r.json()
    assert body["case_id"] == "KAV-20260824-A7K2"
    assert body["matched_pattern_ids"] == "DA-01,DA-03"


def test_get_case_returns_404_when_not_found(monkeypatch):
    from services import store as store_module

    monkeypatch.setattr(store_module, "get_audit_record", lambda case_id: None)

    r = client.get("/case/KAV-20260824-ZZZZ")
    assert r.status_code == 404
    assert r.json() == {"error": "Case not found"}


def test_get_case_returns_503_when_supabase_unavailable(monkeypatch):
    from services import store as store_module

    def _boom(case_id):
        raise store_module.AuditStoreUnavailable("Supabase is not configured")

    monkeypatch.setattr(store_module, "get_audit_record", _boom)

    r = client.get("/case/KAV-20260824-A7K2")
    assert r.status_code == 503
    assert r.json() == {"error": "Audit log unavailable"}


# ---------------------------------------------------------------------------
# URL reputation — second deterministic signal source (PhishTank)
# ---------------------------------------------------------------------------


def _fake_llm_kyc(text: str, grounding: str = "") -> dict:
    return {
        "scam_type": "kyc_bank",
        "risk": 70,
        "confidence": 0.8,
        "signals": ["urgency"],
        "explanation": "KYC scam pattern.",
        "recommended_action": "Do not click the link.",
        "detected_language": "en",
    }


def test_decision_source_includes_url_rep_when_urls_present(monkeypatch):
    from services import classifier as cm

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_kyc)
    monkeypatch.setattr(cm.reputation_service, "get_url_signals", lambda text: [
        {"url": "http://safe.example.com", "status": "clean", "source": "PhishTank"}
    ])

    verdict = cm.analyze("Update your KYC at http://safe.example.com now")
    assert verdict["decision_source"].endswith("+url_rep")


def test_decision_source_has_no_url_rep_suffix_when_no_urls(monkeypatch):
    from services import classifier as cm

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_kyc)
    monkeypatch.setattr(cm.reputation_service, "get_url_signals", lambda text: [])

    verdict = cm.analyze("Update your KYC immediately or your account will be blocked")
    assert "+url_rep" not in verdict["decision_source"]


def test_phishing_url_added_to_signals_and_risk_bumped(monkeypatch):
    from services import classifier as cm

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_kyc)
    monkeypatch.setattr(cm.reputation_service, "get_url_signals", lambda text: [
        {"url": "http://phish.example.com/login", "status": "phishing", "source": "PhishTank"}
    ])

    # Baseline: same inputs, no URL signals, to compute the expected bump.
    monkeypatch.setattr(cm.store_service, "log_signal", lambda r: None)
    monkeypatch.setattr(cm.store_service, "log_audit_record", lambda r: None)
    text = "Update your KYC at http://phish.example.com/login now"

    with_url_rep = cm.analyze(text)
    assert "phishing_url" in with_url_rep["signals"]
    assert with_url_rep["artifacts"]["url_reputation"] == [
        {"url": "http://phish.example.com/login", "status": "phishing", "source": "PhishTank"}
    ]

    monkeypatch.setattr(cm.reputation_service, "get_url_signals", lambda text: [])
    without_url_rep = cm.analyze(text)
    assert "phishing_url" not in without_url_rep["signals"]

    # Risk bump is capped at +8 and never pushes above 100.
    assert with_url_rep["risk"] - without_url_rep["risk"] == 8


def test_risk_bump_is_capped_at_100(monkeypatch):
    from services import classifier as cm

    def _fake_llm_high_risk(text: str, grounding: str = "") -> dict:
        return {
            "scam_type": "digital_arrest", "risk": 98, "confidence": 0.95,
            "signals": ["authority", "fear", "payment"],
            "explanation": "x", "recommended_action": "y", "detected_language": "en",
        }

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_high_risk)
    monkeypatch.setattr(cm.reputation_service, "get_url_signals", lambda text: [
        {"url": "http://phish.example.com/login", "status": "phishing", "source": "PhishTank"}
    ])

    verdict = cm.analyze("CBI digital arrest, transfer now via http://phish.example.com/login")
    assert verdict["risk"] <= 100


def test_artifacts_urls_untouched_alongside_url_reputation(monkeypatch):
    """artifacts.urls stays the existing list[str] of raw URLs; the new
    reputation dicts live in a separate artifacts.url_reputation key."""
    from services import classifier as cm

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_kyc)
    monkeypatch.setattr(cm.reputation_service, "get_url_signals", lambda text: [
        {"url": "http://phish.example.com/login", "status": "phishing", "source": "PhishTank"}
    ])

    text = "Update your KYC at http://phish.example.com/login now"
    verdict = cm.analyze(text)
    assert verdict["artifacts"]["urls"] == ["http://phish.example.com/login"]
    assert isinstance(verdict["artifacts"]["url_reputation"], list)
    assert all(isinstance(s, dict) for s in verdict["artifacts"]["url_reputation"])


def test_phishtank_download_failure_does_not_affect_verdict(monkeypatch):
    """Load-bearing: /analyze must be unaffected by a PhishTank outage —
    same fire-and-forget-style resilience as telemetry/audit."""
    from services import classifier as cm
    from services import reputation as reputation_module

    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_kyc)

    def _boom(text):
        raise RuntimeError("PhishTank is down")

    monkeypatch.setattr(cm.reputation_service, "get_url_signals", _boom)

    text = "Update your KYC at http://example.com now"
    verdict = cm.analyze(text)
    _assert_valid_verdict(verdict)
    assert verdict["scam_type"] == "kyc_bank"
    # Augmentation failed cleanly: no +url_rep suffix, empty reputation list.
    assert "+url_rep" not in verdict["decision_source"]
    assert verdict["artifacts"]["url_reputation"] == []


def test_get_url_signals_real_network_failure_path_via_classifier(monkeypatch):
    """Same as above but exercising the real reputation module (not a mock
    of get_url_signals itself) against a mocked network failure, so the
    classifier-level integration of reputation.py's own error handling is
    covered too."""
    from services import classifier as cm
    from services import reputation as reputation_module

    def _raise_network_error(*args, **kwargs):
        raise RuntimeError("network is down")

    reputation_module._reset_cache_for_tests()
    monkeypatch.setattr(cm.llm_service, "analyze_message", _fake_llm_kyc)
    monkeypatch.setattr("httpx.Client", _raise_network_error)

    text = "Update your KYC at http://example.com now"
    verdict = cm.analyze(text)
    _assert_valid_verdict(verdict)
    # PhishTank being unreachable -> "unknown", never "phishing" -> no bump.
    assert "phishing_url" not in verdict["signals"]
    reputation_module._reset_cache_for_tests()
