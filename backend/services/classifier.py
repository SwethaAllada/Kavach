"""Hybrid decision engine: rules + LLM fusion with graceful fallback.

Public API: analyze(text, language=None, sender=None) -> dict (Verdict-shaped).
Never raises — worst case returns a "unable to analyze, treat with caution"
Verdict so the request path stays 200.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from core import privacy as privacy_module
from core.locales_loader import SUPPORTED_LANGUAGES, get_string
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


# Per-scam_type explanation + recommended_action for the rules-only
# fallback path now lives in locales/<lang>/responses.yaml under
# fallback_templates, read via core.locales_loader.get_string().


# Simple, dependency-free language detection for the fallback path. One
# regex per Unicode script block — cheap and works without any external
# language-detection library. Devanagari is shared by Hindi and Marathi
# (see _MARATHI_WORDS below for how those two are told apart) and also by
# Sanskrit, Maithili, Kashmiri, Nepali, Konkani, and Sindhi — those six have
# no word-marker disambiguator (unlike Marathi, there's no validated list of
# marker words for them) and so auto-detect as "hi" from script alone; they
# remain reachable via the `hint` parameter (e.g. a UI language selector).
_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
_TELUGU = re.compile(r"[ఀ-౿]")
_TAMIL = re.compile(r"[஀-௿]")
_KANNADA = re.compile(r"[ಀ-೿]")
_MALAYALAM = re.compile(r"[ഀ-ൿ]")
_BENGALI = re.compile(r"[ঀ-৿]")
_GUJARATI = re.compile(r"[઀-૿]")
_GURMUKHI = re.compile(r"[਀-੿]")  # Punjabi
_ORIYA = re.compile(r"[଀-୿]")
_URDU = re.compile(r"[؀-ۿݐ-ݿ]")  # Arabic + Arabic Supplement blocks
_OL_CHIKI = re.compile(r"[᱐-᱿]")  # Santali

# Assamese uses ৰ (U+09F0) and ৱ (U+09F1) for RA/WA — code points within the
# Bengali Unicode block that standard Bengali orthography does not use (it
# uses U+09B0 for RA instead). This is a genuine script-level distinguisher,
# not a heuristic — unlike Marathi vs. Hindi, Assamese vs. Bengali can be
# told apart by character presence alone.
_ASSAMESE_MARKERS = re.compile(r"[ৰৱ]")

# Marathi shares Devanagari with Hindi, so script alone can't distinguish
# them. These are common Marathi function words with no equivalent spelling
# in standard Hindi — their presence in a Devanagari-script message is a
# reasonable signal the message is Marathi, not Hindi. Deliberately small
# and conservative: a false "hi" for an ambiguous/short Marathi message is
# safe (falls back to the existing, well-tested Hindi path) and preferred
# over misdetecting Hindi as Marathi.
_MARATHI_WORDS = re.compile(r"आहे|नाही|आपण|करा")


def _detect_language(text: str, hint: Optional[str] = None) -> str:
    if hint in SUPPORTED_LANGUAGES:
        return hint
    if "te" in SUPPORTED_LANGUAGES and _TELUGU.search(text):
        return "te"
    if "ta" in SUPPORTED_LANGUAGES and _TAMIL.search(text):
        return "ta"
    if "kn" in SUPPORTED_LANGUAGES and _KANNADA.search(text):
        return "kn"
    if "ml" in SUPPORTED_LANGUAGES and _MALAYALAM.search(text):
        return "ml"
    if "gu" in SUPPORTED_LANGUAGES and _GUJARATI.search(text):
        return "gu"
    if "pa" in SUPPORTED_LANGUAGES and _GURMUKHI.search(text):
        return "pa"
    if "or" in SUPPORTED_LANGUAGES and _ORIYA.search(text):
        return "or"
    if "ur" in SUPPORTED_LANGUAGES and _URDU.search(text):
        return "ur"
    if "sat" in SUPPORTED_LANGUAGES and _OL_CHIKI.search(text):
        return "sat"
    if _BENGALI.search(text):
        if "as" in SUPPORTED_LANGUAGES and _ASSAMESE_MARKERS.search(text):
            return "as"
        if "bn" in SUPPORTED_LANGUAGES:
            return "bn"
    if _DEVANAGARI.search(text):
        if "mr" in SUPPORTED_LANGUAGES and _MARATHI_WORDS.search(text):
            return "mr"
        if "hi" in SUPPORTED_LANGUAGES:
            return "hi"
    return "en"


def _extract_artifacts(text: str) -> dict:
    urls = re.findall(r"https?://\S+", text)
    phones = re.findall(r"(?:\+?\d[\d\s\-]{7,}\d)", text)
    return {"urls": urls, "phones": phones}


def _safe_verdict(text: str, detected_language: str) -> dict:
    # This is the last-resort path (rules_classify itself raised) — the
    # literal English strings here are the ultimate hardcoded backstop
    # get_string()'s `default` falls through to; they are intentionally
    # NOT locale-driven so this path can never fail even if locales/ itself
    # is broken.
    explanation = get_string(
        detected_language, "fallback_templates", "other", "explanation",
        default="Unable to analyze this message right now. Treat it with caution.",
    )
    action = get_string(
        detected_language, "fallback_templates", "other", "recommended_action",
        default="Do not share OTPs, do not click links. If unsure, report to 1930.",
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
        "explanation": explanation,
        "recommended_action": action,
        "report": {"channels": REPORT_CHANNELS, "prefilled_summary": ""},
        "detected_language": detected_language,
    }


def _fallback_from_rules(rules_out: dict, text: str, detected_language: str) -> dict:
    scam_type = rules_out["scam_type"]
    explanation = get_string(
        detected_language, "fallback_templates", scam_type, "explanation",
        default=get_string(
            "en", "fallback_templates", "other", "explanation",
            default="This message shows some suspicious signals. Treat it with caution.",
        ),
    )
    action = get_string(
        detected_language, "fallback_templates", scam_type, "recommended_action",
        default=get_string(
            "en", "fallback_templates", "other", "recommended_action",
            default="Do not share OTPs, do not click links, verify with the official channel.",
        ),
    )

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


def analyze(text: str, language: Optional[str] = None, sender: Optional[str] = None) -> dict:
    """Public entry point. Always returns a valid Verdict dict; never raises.

    `sender` is an optional structured field (e.g. a DLT header, 10-digit
    mobile number, or shortcode) carried alongside `text`, never concatenated
    into it. Not yet consumed by rules/LLM/RAG — reserved for a future
    sender-aware signal (see F2 sender.py) so callers can start passing it
    now without their text being misread as containing a header.
    """
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


def classify(text: str, language: Optional[str] = None, sender: Optional[str] = None) -> dict:
    """Backwards-compatible alias."""
    return analyze(text, language, sender)
