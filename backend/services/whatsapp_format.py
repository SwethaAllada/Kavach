"""Verdict → WhatsApp-friendly plain-text formatter.

Pure function: given a fully-formed Verdict, return a single string ready to
send back over Twilio's SMS/WhatsApp channel. No HTML, no markdown syntax
Twilio wouldn't render, no side effects.

The engine already writes `explanation` and `recommended_action` in the
detected language (English / Hindi / Telugu), so this module does no
translation — it only assembles the pieces and honors WhatsApp's ~1600-char
message limit.
"""

from __future__ import annotations

from typing import Optional

# Twilio SMS is 1600 chars; WhatsApp is 4096 but many carriers render only the
# first ~1500 cleanly. We target 1500 as a safe hard cap.
MAX_MESSAGE_CHARS = 1500

# Human-readable scam-type labels per language. Only labels are localized —
# the actual explanation/action text comes from the verdict itself.
_SCAM_LABELS: dict[str, dict[str, str]] = {
    "digital_arrest":       {"en": "Digital Arrest",       "hi": "डिजिटल अरेस्ट",    "te": "డిజిటల్ అరెస్ట్"},
    "investment_stock":     {"en": "Investment / Trading", "hi": "निवेश / ट्रेडिंग",   "te": "పెట్టుబడి / ట్రేడింగ్"},
    "kyc_bank":             {"en": "Bank / KYC",           "hi": "बैंक / KYC",       "te": "బ్యాంక్ / KYC"},
    "courier_parcel":       {"en": "Courier / Customs",    "hi": "कूरियर / कस्टम",   "te": "కొరియర్ / కస్టమ్స్"},
    "job_task":             {"en": "Task Job",             "hi": "टास्क जॉब",        "te": "టాస్క్ ఉద్యోగం"},
    "loan_app":             {"en": "Loan App",             "hi": "लोन ऐप",           "te": "లోన్ యాప్"},
    "lottery_prize":        {"en": "Lottery / Prize",      "hi": "लॉटरी / इनाम",     "te": "లాటరీ / బహుమతి"},
    "tech_support":         {"en": "Tech Support",         "hi": "टेक सपोर्ट",       "te": "టెక్ సపోర్ట్"},
    "upi_collect_request":  {"en": "UPI Collect Scam",     "hi": "UPI कलेक्ट",       "te": "UPI కలెక్ట్"},
    "romance":              {"en": "Romance",              "hi": "रोमांस",            "te": "రొమాన్స్"},
    "deepfake_voice":       {"en": "Deepfake Voice",       "hi": "डीपफेक वॉइस",       "te": "డీప్‌ఫేక్ వాయిస్"},
    "other":                {"en": "Suspicious",           "hi": "संदिग्ध",           "te": "అనుమానాస్పద"},
    "likely_safe":          {"en": "Likely Safe",          "hi": "संभवतः सुरक्षित",   "te": "సురక్షితం"},
}

# Fixed sentences that live in this module (not the verdict) — headline verdict
# lines and section labels.
_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "brand":            "Kavach",
        "scam":             "⚠️ LIKELY SCAM",
        "caution":          "⚠️ Suspicious — be careful",
        "safe":             "✅ Looks safe",
        "risk_line":        "{headline} — {label} (risk {risk}/100)",
        "why":              "Why:",
        "action":           "What to do:",
        "report_prefix":    "Report now:",
        "summary_available":"A ready-to-file complaint summary is available in the Kavach app.",
        "footer":           "— Kavach (guidance only; we never file for you)",
        "err":              "Sorry, we couldn't analyze that message just now. Please try again in a moment.",
    },
    "hi": {
        "brand":            "Kavach",
        "scam":             "⚠️ संभावित घोटाला",
        "caution":          "⚠️ संदिग्ध — सावधान रहें",
        "safe":             "✅ सुरक्षित लगता है",
        "risk_line":        "{headline} — {label} (जोखिम {risk}/100)",
        "why":              "क्यों:",
        "action":           "क्या करें:",
        "report_prefix":    "अभी रिपोर्ट करें:",
        "summary_available":"तैयार शिकायत सारांश Kavach ऐप में उपलब्ध है।",
        "footer":           "— Kavach (केवल मार्गदर्शन; हम आपकी ओर से शिकायत दर्ज नहीं करते)",
        "err":              "क्षमा करें, अभी संदेश का विश्लेषण नहीं हो सका। कृपया दोबारा प्रयास करें।",
    },
    "te": {
        "brand":            "Kavach",
        "scam":             "⚠️ మోసం అని అనుమానం",
        "caution":          "⚠️ అనుమానాస్పదం — జాగ్రత్తగా ఉండండి",
        "safe":             "✅ సురక్షితంగా కనిపిస్తుంది",
        "risk_line":        "{headline} — {label} (రిస్క్ {risk}/100)",
        "why":              "ఎందుకు:",
        "action":           "ఏం చేయాలి:",
        "report_prefix":    "ఇప్పుడే ఫిర్యాదు చేయండి:",
        "summary_available":"సిద్ధంగా ఉన్న ఫిర్యాదు సారాంశం Kavach యాప్‌లో లభిస్తుంది.",
        "footer":           "— Kavach (మార్గదర్శకం మాత్రమే; మేము మీ తరపున ఫిర్యాదు చేయము)",
        "err":              "క్షమించండి, ప్రస్తుతం సందేశాన్ని విశ్లేషించలేకపోయాం. దయచేసి కొద్దిసేపటి తర్వాత ప్రయత్నించండి.",
    },
}


def _lang(verdict: dict) -> str:
    lang = str((verdict or {}).get("detected_language") or "en")
    return lang if lang in _STRINGS else "en"


def _scam_label(scam_type: str, lang: str) -> str:
    entry = _SCAM_LABELS.get(scam_type) or _SCAM_LABELS["other"]
    return entry.get(lang) or entry.get("en") or scam_type


def _headline(scam_type: str, risk: int, lang: str) -> str:
    s = _STRINGS[lang]
    if scam_type == "likely_safe" or risk < 40:
        return s["safe"]
    if risk < 70:
        return s["caution"]
    return s["scam"]


def _top_channel_line(verdict: dict, lang: str) -> Optional[str]:
    """First line for the report block, e.g. 'Report now: call 1930'."""
    report = (verdict or {}).get("report") or {}
    if not report.get("should_report"):
        return None
    channels = report.get("channels") or []
    if not channels:
        return None
    top = channels[0]
    name = str(top.get("name") or "").strip()
    value = str(top.get("value") or "").strip()
    if not value:
        return None
    prefix = _STRINGS[lang]["report_prefix"]
    return f"{prefix} {name} ({value})" if name else f"{prefix} {value}"


def _clip(text: str, limit: int) -> str:
    """Trim to `limit` chars on a word boundary if possible, adding an ellipsis."""
    if len(text) <= limit:
        return text
    # Reserve 1 char for the ellipsis.
    cut = text[: max(1, limit - 1)]
    space = cut.rfind(" ")
    if space > int(limit * 0.6):
        cut = cut[:space]
    return cut.rstrip() + "…"


def verdict_to_whatsapp_text(verdict: dict) -> str:
    """Return a WhatsApp-ready plain-text reply for `verdict`.

    Never raises. On a bad/empty verdict returns a short generic error message
    in English so the user still gets *something* back.
    """
    try:
        if not isinstance(verdict, dict) or not verdict.get("scam_type"):
            return _STRINGS["en"]["err"]

        lang = _lang(verdict)
        s = _STRINGS[lang]
        scam_type = str(verdict.get("scam_type") or "other")
        risk = int(verdict.get("risk") or 0)

        parts: list[str] = []

        # Line 1 — brand + risk headline (large, scannable).
        headline = _headline(scam_type, risk, lang)
        label = _scam_label(scam_type, lang)
        parts.append(s["risk_line"].format(headline=headline, label=label, risk=risk))

        # Section: why (from the verdict's explanation).
        explanation = str(verdict.get("explanation") or "").strip()
        if explanation:
            parts.append("")
            parts.append(f"{s['why']} {explanation}")

        # Section: what to do (from the verdict's recommended_action).
        action = str(verdict.get("recommended_action") or "").strip()
        if action:
            parts.append("")
            parts.append(f"{s['action']} {action}")

        # Reporting block — only if the engine says should_report.
        channel_line = _top_channel_line(verdict, lang)
        if channel_line:
            parts.append("")
            parts.append(channel_line)
            parts.append(s["summary_available"])

        # Footer keeps expectations honest (guidance only).
        parts.append("")
        parts.append(s["footer"])

        body = "\n".join(parts)
        return _clip(body, MAX_MESSAGE_CHARS)
    except Exception:
        # Never let a formatting bug surface as a 500 to Twilio.
        return _STRINGS["en"]["err"]
