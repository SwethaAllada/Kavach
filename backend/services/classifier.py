"""Hybrid decision engine: rules + LLM fusion with graceful fallback.

Public API: analyze(text, language=None) -> dict (Verdict-shaped).
Never raises — worst case returns a "unable to analyze, treat with caution"
Verdict so the request path stays 200.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from core import privacy as privacy_module
from services import llm as llm_service
from services import rag as rag_service
from services import report as report_service
from services import store as store_service
from services.llm import LLMUnavailable
from services.rules import SCAM_TAXONOMY, rules_classify

# Bounds on the RAG confidence nudge — never allowed to move confidence by
# more than this in either direction. Retrieval augments; it does not decide.
_RAG_CONF_NUDGE_CAP = 0.10
# If the final decision is likely_safe with confidence at least this high,
# RAG can populate matched_patterns for transparency but MUST NOT flip the
# decision or bump risk. Protects the false-positive rate.
_SAFE_LOCK_CONFIDENCE = 0.70

log = logging.getLogger(__name__)


REPORT_CHANNELS = ["1930", "cybercrime.gov.in", "Chakshu"]


# Templated explanation + recommended_action per scam_type, per language.
# Used in the rules-only fallback path when the LLM is unavailable.
_TEMPLATES: dict[str, dict[str, tuple[str, str]]] = {
    "digital_arrest": {
        "en": (
            "Signals of a 'digital arrest' scam: fake authority (police/CBI/ED), "
            "fear tactics, and payment demand. Real agencies never arrest over video calls.",
            "Do not pay. Do not stay on the call. Report to 1930 and cybercrime.gov.in.",
        ),
        "hi": (
            "'डिजिटल अरेस्ट' घोटाले के संकेत: नकली अधिकारी, डर, भुगतान की मांग। "
            "असली एजेंसियां वीडियो कॉल पर गिरफ्तार नहीं करतीं।",
            "पैसे न भेजें। कॉल तुरंत काटें। 1930 और cybercrime.gov.in पर शिकायत करें।",
        ),
        "te": (
            "'డిజిటల్ అరెస్ట్' మోసం సంకేతాలు: నకిలీ అధికారి, భయపెట్టడం, డబ్బు అడగడం. "
            "నిజమైన ఏజెన్సీలు వీడియో కాల్‌లో అరెస్ట్ చేయవు.",
            "డబ్బు పంపవద్దు. కాల్ కట్ చేయండి. 1930 మరియు cybercrime.gov.in లో ఫిర్యాదు చేయండి.",
        ),
    },
    "kyc_bank": {
        "en": (
            "Signals of a KYC/bank scam: urgent account-block warning and a request to verify or share credentials.",
            "Do not click links. Do not share OTP/PIN. Call your bank on the number printed on your card.",
        ),
        "hi": (
            "KYC/बैंक घोटाले के संकेत: खाता बंद होने की चेतावनी और OTP/जानकारी मांगना।",
            "किसी लिंक पर क्लिक न करें। OTP/PIN साझा न करें। कार्ड पर छपे नंबर से बैंक को कॉल करें।",
        ),
        "te": (
            "KYC/బ్యాంక్ మోసం సంకేతాలు: ఖాతా బ్లాక్ హెచ్చరిక, OTP/వివరాలు అడగడం.",
            "లింక్‌లపై క్లిక్ చేయవద్దు. OTP/PIN షేర్ చేయవద్దు. కార్డుపై ఉన్న నంబర్‌కు బ్యాంక్‌ను కాల్ చేయండి.",
        ),
    },
    "courier_parcel": {
        "en": (
            "Signals of a fake courier/customs scam: 'parcel held' and demand for a fee or personal details.",
            "Do not pay. Verify the parcel directly with the courier's official website or app.",
        ),
        "hi": (
            "नकली कूरियर घोटाले के संकेत: 'पार्सल रोका गया' और शुल्क/जानकारी की मांग।",
            "पैसे न दें। कूरियर की आधिकारिक वेबसाइट/ऐप पर स्थिति देखें।",
        ),
        "te": (
            "నకిలీ కొరియర్ మోసం సంకేతాలు: 'పార్సెల్ ఆపబడింది' అనీ ఫీజు అడగడం.",
            "డబ్బు చెల్లించవద్దు. అధికారిక కొరియర్ వెబ్‌సైట్/యాప్‌లో స్థితి తనిఖీ చేయండి.",
        ),
    },
    "investment_stock": {
        "en": (
            "Signals of an investment scam: guaranteed returns, VIP tips, or WhatsApp/Telegram trading groups.",
            "Guaranteed returns do not exist. Do not send money or join paid groups. Report to 1930.",
        ),
        "hi": (
            "निवेश घोटाले के संकेत: गारंटीड रिटर्न, VIP टिप्स, या ट्रेडिंग ग्रुप।",
            "गारंटीड रिटर्न नहीं होते। पैसा न भेजें, ग्रुप न जॉइन करें। 1930 पर शिकायत करें।",
        ),
        "te": (
            "పెట్టుబడి మోసం సంకేతాలు: గ్యారంటీ లాభాలు, VIP టిప్స్, ట్రేడింగ్ గ్రూప్‌లు.",
            "గ్యారంటీ లాభాలు ఉండవు. డబ్బు పంపవద్దు. 1930 కి ఫిర్యాదు చేయండి.",
        ),
    },
    "lottery_prize": {
        "en": (
            "Signals of a lottery/prize scam: 'you have won' with a processing-fee or bank-details request.",
            "Do not pay any fee. Do not share bank details. It is a scam.",
        ),
        "hi": (
            "लॉटरी घोटाले के संकेत: 'आपने जीता है' और प्रोसेसिंग फीस या बैंक विवरण मांगना।",
            "कोई शुल्क न दें। बैंक जानकारी साझा न करें। यह घोटाला है।",
        ),
        "te": (
            "లాటరీ మోసం సంకేతాలు: 'మీరు గెలిచారు' అని ఫీజు లేదా బ్యాంక్ వివరాలు అడగడం.",
            "ఎలాంటి ఫీజు చెల్లించవద్దు. బ్యాంక్ వివరాలు షేర్ చేయవద్దు. ఇది మోసం.",
        ),
    },
    "upi_collect_request": {
        "en": (
            "UPI collect / refund request: scammers get you to APPROVE a payment while promising a refund.",
            "You never scan a QR or approve a request to RECEIVE money. Decline the request.",
        ),
        "hi": (
            "UPI कलेक्ट/रिफंड घोटाला: रिफंड के बहाने आपसे भुगतान APPROVE कराते हैं।",
            "पैसे प्राप्त करने के लिए QR स्कैन या रिक्वेस्ट अप्रूव नहीं होती। रिक्वेस्ट रिजेक्ट करें।",
        ),
        "te": (
            "UPI కలెక్ట్/రిఫండ్ మోసం: రిఫండ్ పేరుతో మీచేత చెల్లింపును APPROVE చేయిస్తారు.",
            "డబ్బు అందుకోవడానికి QR స్కాన్ లేదా అభ్యర్థన ఆమోదించాల్సిన అవసరం లేదు. తిరస్కరించండి.",
        ),
    },
    "job_task": {
        "en": (
            "Signals of a task/work-from-home scam: promised earnings for likes/ratings, then a 'prepaid task'.",
            "Do not pay any prepaid task fee. Legitimate jobs never ask you to pay to earn.",
        ),
        "hi": (
            "टास्क/वर्क-फ्रॉम-होम घोटाले के संकेत: लाइक/रेटिंग के बदले कमाई, फिर 'प्रीपेड टास्क'।",
            "कोई प्रीपेड टास्क शुल्क न दें। असली नौकरी कमाने के लिए पैसे नहीं मांगती।",
        ),
        "te": (
            "టాస్క్/వర్క్-ఫ్రమ్-హోమ్ మోసం సంకేతాలు: లైక్/రేటింగ్‌కి డబ్బు, తర్వాత 'ప్రీపెయిడ్ టాస్క్'.",
            "ప్రీపెయిడ్ టాస్క్ ఫీజు చెల్లించవద్దు. నిజమైన ఉద్యోగాలు మీ నుండి డబ్బు అడగవు.",
        ),
    },
    "loan_app": {
        "en": (
            "Signals of a loan-app scam: instant loan, no documents, upfront processing fee.",
            "Do not pay any advance fee. Use only RBI-registered lenders.",
        ),
        "hi": (
            "लोन ऐप घोटाले के संकेत: तुरंत लोन, कोई दस्तावेज़ नहीं, अग्रिम फीस।",
            "कोई अग्रिम फीस न दें। केवल RBI-पंजीकृत लेंडर से ऋण लें।",
        ),
        "te": (
            "లోన్ యాప్ మోసం సంకేతాలు: వెంటనే రుణం, డాక్యుమెంట్లు లేవు, ముందస్తు ఫీజు.",
            "ఎలాంటి ముందస్తు ఫీజు చెల్లించవద్దు. RBI-రిజిస్టర్డ్ లెండర్‌లను మాత్రమే ఉపయోగించండి.",
        ),
    },
    "tech_support": {
        "en": (
            "Signals of a tech-support scam: 'your computer is infected' with a request to install remote-access software.",
            "Do not install AnyDesk / TeamViewer for callers. Microsoft never calls you unsolicited.",
        ),
        "hi": (
            "टेक-सपोर्ट घोटाले के संकेत: 'आपका कंप्यूटर संक्रमित है' और रिमोट सॉफ्टवेयर इंस्टॉल कराना।",
            "AnyDesk/TeamViewer अनजान कॉलर के लिए इंस्टॉल न करें।",
        ),
        "te": (
            "టెక్-సపోర్ట్ మోసం సంకేతాలు: 'మీ కంప్యూటర్ ఇన్ఫెక్ట్ అయింది' అని రిమోట్ యాక్సెస్ ఇన్‌స్టాల్ చేయమనడం.",
            "అపరిచితుల కోసం AnyDesk/TeamViewer ఇన్‌స్టాల్ చేయవద్దు.",
        ),
    },
    "romance": {
        "en": (
            "Signals of a romance scam: online partner asking for money, gifts, or airport/customs help.",
            "Do not send money to someone you have not met. Report to 1930.",
        ),
        "hi": (
            "रोमांस घोटाले के संकेत: ऑनलाइन साथी पैसे या कस्टम/एयरपोर्ट मदद माँगे।",
            "जिससे कभी नहीं मिले उसे पैसे न भेजें। 1930 पर शिकायत करें।",
        ),
        "te": (
            "రొమాన్స్ మోసం సంకేతాలు: ఆన్‌లైన్ పరిచయస్తులు డబ్బు లేదా కస్టమ్స్ సహాయం అడగడం.",
            "కలవని వారికి డబ్బు పంపవద్దు. 1930 కి ఫిర్యాదు చేయండి.",
        ),
    },
    "deepfake_voice": {
        "en": (
            "Signals of a deepfake-voice scam: urgent voice message from a 'family member' asking for money.",
            "Call the person back on their known number before sending anything.",
        ),
        "hi": (
            "डीपफेक-वॉइस घोटाले के संकेत: 'परिवार' का जरूरी वॉइस मैसेज पैसे मांगते हुए।",
            "पैसा भेजने से पहले उनके ज्ञात नंबर पर स्वयं कॉल करें।",
        ),
        "te": (
            "డీప్‌ఫేక్-వాయిస్ మోసం సంకేతాలు: 'కుటుంబం' నుండి అత్యవసర వాయిస్ మెసేజ్‌లో డబ్బు అడగడం.",
            "డబ్బు పంపే ముందు వారి తెలిసిన నంబర్‌కు మీరే కాల్ చేయండి.",
        ),
    },
    "other": {
        "en": (
            "This message shows some suspicious signals. Treat it with caution.",
            "Do not share OTPs, do not click links, verify with the official channel.",
        ),
        "hi": (
            "इस संदेश में कुछ संदिग्ध संकेत हैं। सावधानी बरतें।",
            "OTP साझा न करें, लिंक पर क्लिक न करें, आधिकारिक चैनल से जांचें।",
        ),
        "te": (
            "ఈ సందేశంలో అనుమానాస్పద సంకేతాలు ఉన్నాయి. జాగ్రత్తగా ఉండండి.",
            "OTP షేర్ చేయవద్దు, లింక్‌లపై క్లిక్ చేయవద్దు, అధికారిక ఛానెల్‌లో ధృవీకరించండి.",
        ),
    },
    "likely_safe": {
        "en": (
            "No clear scam signals detected. This message looks likely safe, but stay alert.",
            "If in doubt, verify with the sender through a known contact channel.",
        ),
        "hi": (
            "कोई स्पष्ट घोटाले के संकेत नहीं मिले। संदेश संभवतः सुरक्षित लगता है, फिर भी सतर्क रहें।",
            "संदेह हो तो प्रेषक से ज्ञात संपर्क माध्यम पर पुष्टि करें।",
        ),
        "te": (
            "స్పష్టమైన మోసం సంకేతాలు లేవు. సందేశం సురక్షితంగా కనిపిస్తుంది, అయినా జాగ్రత్తగా ఉండండి.",
            "సందేహం ఉంటే పంపినవారిని తెలిసిన ఛానెల్ ద్వారా ధృవీకరించండి.",
        ),
    },
}


# Simple, dependency-free language detection for the fallback path.
_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
_TELUGU = re.compile(r"[ఀ-౿]")


def _detect_language(text: str, hint: Optional[str] = None) -> str:
    if hint in ("en", "hi", "te"):
        return hint
    if _TELUGU.search(text):
        return "te"
    if _DEVANAGARI.search(text):
        return "hi"
    return "en"


def _extract_artifacts(text: str) -> dict:
    urls = re.findall(r"https?://\S+", text)
    phones = re.findall(r"(?:\+?\d[\d\s\-]{7,}\d)", text)
    return {"urls": urls, "phones": phones}


def _safe_verdict(text: str, detected_language: str) -> dict:
    tmpl_en = (
        "Unable to analyze this message right now. Treat it with caution.",
        "Do not share OTPs, do not click links. If unsure, report to 1930.",
    )
    return {
        "scam_type": "other",
        "risk": 50,
        "confidence": 0.2,
        "decision_source": "safe_default",
        "fallback_used": True,
        "signals": [],
        "matched_patterns": [],
        "artifacts": _extract_artifacts(text),
        "explanation": tmpl_en[0],
        "recommended_action": tmpl_en[1],
        "report": {"channels": REPORT_CHANNELS, "prefilled_summary": ""},
        "detected_language": detected_language,
    }


def _fallback_from_rules(rules_out: dict, text: str, detected_language: str) -> dict:
    scam_type = rules_out["scam_type"]
    templates = _TEMPLATES.get(scam_type) or _TEMPLATES["other"]
    explanation, action = templates.get(detected_language) or templates["en"]

    # Cap fallback confidence modestly.
    rule_risk = rules_out["rule_risk"]
    confidence = min(0.6, 0.3 + 0.3 * (rule_risk / 100.0))

    return {
        "scam_type": scam_type,
        "risk": rule_risk,
        "confidence": round(confidence, 2),
        "decision_source": "rules_fallback",
        "fallback_used": True,
        "signals": rules_out["signals"],
        "matched_patterns": [],
        "artifacts": _extract_artifacts(text),
        "explanation": explanation,
        "recommended_action": action,
        "report": {"channels": REPORT_CHANNELS, "prefilled_summary": ""},
        "detected_language": detected_language,
    }


def _fuse(rules_out: dict, llm_out: dict, text: str) -> dict:
    """Combine rules prior with LLM verdict.

    Fusion rules:
      - scam_type: prefer LLM's, but if LLM confidence is low (< 0.5) and rules
        detected a specific scam_type with hits, keep the rules' scam_type.
      - signals: union of both.
      - risk: weighted blend. Weight the LLM higher when it is confident.
      - confidence: bumped up when rules and LLM AGREE on scam_type,
        pulled down when they DISAGREE.
    """
    llm_conf = llm_out["confidence"]
    llm_scam = llm_out["scam_type"]
    rule_scam = rules_out["scam_type"]

    agree = llm_scam == rule_scam and rule_scam not in ("other", "likely_safe")

    if llm_conf < 0.5 and rule_scam not in ("other", "likely_safe"):
        final_scam = rule_scam
    else:
        final_scam = llm_scam

    signals = sorted(set(rules_out["signals"]) | set(llm_out["signals"]))

    # Weighted risk blend.
    w_llm = 0.4 + 0.5 * llm_conf  # 0.4 .. 0.9
    w_rule = 1.0 - w_llm
    fused_risk = int(round(w_llm * llm_out["risk"] + w_rule * rules_out["rule_risk"]))
    fused_risk = max(0, min(100, fused_risk))

    # Confidence fusion.
    if agree:
        fused_conf = min(0.95, llm_conf + 0.15)
    elif llm_scam != rule_scam and rule_scam not in ("other", "likely_safe"):
        fused_conf = max(0.2, llm_conf - 0.15)
    else:
        fused_conf = llm_conf

    return {
        "scam_type": final_scam,
        "risk": fused_risk,
        "confidence": round(fused_conf, 2),
        "decision_source": "rules+llm",
        "fallback_used": False,
        "signals": signals,
        "matched_patterns": [],
        "artifacts": _extract_artifacts(text),
        "explanation": llm_out["explanation"],
        "recommended_action": llm_out["recommended_action"],
        "report": {"channels": REPORT_CHANNELS, "prefilled_summary": ""},
        "detected_language": llm_out["detected_language"],
    }


def _safe_retrieve(text: str) -> list[dict]:
    """rag.retrieve wrapped so it can never raise into the request path."""
    try:
        return rag_service.retrieve(text, top_k=3)
    except Exception as e:
        log.warning("rag.retrieve raised (swallowed): %s", e)
        return []


def _filter_hits_for_verdict(hits: list[dict], final_scam_type: str) -> list[dict]:
    """Decide which retrieved hits to attach as matched_patterns.

    - For a specific scam_type, prefer same-category hits; only fall back to
      cross-category hits when no same-category hit was retrieved.
    - For likely_safe, attach nothing — showing "here are the phishing patterns
      that partially match your legit OTP" would confuse users.
    - For 'other', attach the top hit as advisory context.
    """
    if not hits:
        return []
    if final_scam_type == "likely_safe":
        return []
    same = [h for h in hits if h.get("category") == final_scam_type]
    if same:
        return same[:3]
    if final_scam_type == "other":
        return hits[:1]
    # Confident specific type but no same-category hit — don't fabricate
    # citations from a different category.
    return []


def _apply_rag(verdict: dict, hits: list[dict]) -> dict:
    """Augment `verdict` in place with matched_patterns + a capped confidence
    nudge. Never changes scam_type or is_scam-worthy risk.
    """
    if not hits:
        verdict["matched_patterns"] = []
        return verdict

    final_type = verdict["scam_type"]
    confidence = verdict["confidence"]

    # SAFE LOCK: if the engine is confidently likely_safe, RAG must not
    # flip it. Attach nothing and do not nudge confidence up.
    if final_type == "likely_safe" and confidence >= _SAFE_LOCK_CONFIDENCE:
        verdict["matched_patterns"] = []
        return verdict

    attached = _filter_hits_for_verdict(hits, final_type)
    verdict["matched_patterns"] = [
        {
            "id": h["id"],
            "category": h["category"],
            "title": h["title"],
            "similarity": h["similarity"],
            "source": h.get("source", ""),
            "matched_indicators": h.get("matched_indicators", []),
        }
        for h in attached
    ]

    if attached:
        # Confidence nudge: +0.05 per same-category hit, capped by
        # _RAG_CONF_NUDGE_CAP. Only nudges UP when we have real agreement.
        same_cat = [h for h in attached if h["category"] == final_type]
        if same_cat and final_type not in ("likely_safe", "other"):
            nudge = min(_RAG_CONF_NUDGE_CAP, 0.05 * len(same_cat))
            verdict["confidence"] = round(min(0.98, confidence + nudge), 2)
        # Promote decision_source only when RAG actually contributed.
        if verdict["decision_source"] == "rules+llm":
            verdict["decision_source"] = "rules+llm+rag"
        elif verdict["decision_source"] == "rules_fallback":
            verdict["decision_source"] = "rules_fallback+rag"

    return verdict


def analyze(text: str, language: Optional[str] = None) -> dict:
    """Public entry point. Always returns a valid Verdict dict; never raises."""
    text = text or ""
    detected_language = _detect_language(text, language)

    # 1. Deterministic prior — always runs.
    try:
        rules_out = rules_classify(text)
    except Exception as e:
        log.exception("rules_classify unexpectedly failed: %s", e)
        return _safe_verdict(text, detected_language)

    # 2. Retrieval — always runs, never blocks. Used to (a) ground the LLM
    #    prompt, (b) populate matched_patterns after the decision.
    hits = _safe_retrieve(text)
    grounding = rag_service.format_grounding_context(hits) if hits else ""

    # 3. Real LLM call, with fallback to rules-only. Grounding is advisory.
    try:
        llm_out = llm_service.analyze_message(text, grounding=grounding)
        if llm_out.get("scam_type") not in SCAM_TAXONOMY:
            llm_out["scam_type"] = "other"
        verdict = _fuse(rules_out, llm_out, text)
    except LLMUnavailable as e:
        log.warning("LLM unavailable, falling back to rules: %s", e)
        verdict = _fallback_from_rules(rules_out, text, detected_language)
    except Exception as e:
        log.exception("Unexpected error in classifier: %s", e)
        try:
            verdict = _fallback_from_rules(rules_out, text, detected_language)
        except Exception:
            return _safe_verdict(text, detected_language)

    # 4. Attach retrieval evidence. Never overrides the decision above.
    try:
        verdict = _apply_rag(verdict, hits)
    except Exception as e:
        log.warning("rag augmentation failed (swallowed): %s", e)
        verdict.setdefault("matched_patterns", [])

    # 5. Guided reporting. Purely additive: reads verdict + original text,
    #    writes only verdict["report"]. Never raises into the request path
    #    and never touches scam_type / risk / signals / confidence /
    #    matched_patterns.
    try:
        verdict["report"] = report_service.build_report(verdict, text)
    except Exception as e:
        log.warning("report.build_report failed (swallowed): %s", e)
        verdict.setdefault(
            "report", {"channels": REPORT_CHANNELS, "prefilled_summary": ""}
        )

    # 6. Anonymized telemetry — fire-and-forget. Reads a whitelisted subset
    #    of the verdict, never sees the original text. Any failure below
    #    is swallowed; the returned verdict is byte-identical whether or
    #    not telemetry is available.
    try:
        record = privacy_module.to_anonymized_record(verdict)
        store_service.log_signal(record)
    except Exception as e:
        log.warning("telemetry failed (swallowed): %s", e)

    return verdict


def classify(text: str, language: Optional[str] = None) -> dict:
    """Backwards-compatible alias."""
    return analyze(text, language)
