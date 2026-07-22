"""Guided fraud-reporting package builder.

Given a finalized verdict + the original message, produces a paste-ready
complaint description, an ordered list of official Indian reporting channels,
and a scam-type-specific evidence checklist. Never submits anything anywhere.

Design constraints:
  - Language-aware: prefilled_summary is written in verdict.detected_language
    (en | hi | te), falling back to English.
  - Never fabricates data. Amount, date, personal info are left as clearly
    marked [PLACEHOLDERS] the user fills in.
  - No network calls, no external I/O, no `httpx` / `requests` — this module
    only rearranges what the engine already produced.
  - Never raises: on any unexpected input returns a minimal safe report.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Channels
# ---------------------------------------------------------------------------

_CH_1930 = {
    "name": "Cyber Crime Helpline 1930",
    "type": "phone",
    "value": "1930",
    "when": "Call immediately if you have lost money or shared bank/OTP details.",
}
_CH_PORTAL = {
    "name": "National Cyber Crime Reporting Portal",
    "type": "url",
    "value": "https://cybercrime.gov.in",
    "when": "File a written complaint with evidence (screenshots, transaction IDs, caller number).",
}
_CH_CHAKSHU = {
    "name": "Chakshu (Sanchar Saathi)",
    "type": "url",
    "value": "https://sancharsaathi.gov.in/sfc/",
    "when": "Report the suspicious phone number or SMS so the telecom department can block it.",
}


# ---------------------------------------------------------------------------
# Impersonated-entity heuristic (used for the "claiming to be from X" clause)
# ---------------------------------------------------------------------------

_ENTITY_MAP = {
    "digital_arrest": ("CBI", "central agency"),
    "kyc_bank": ("your bank", "बैंक", "బ్యాంక్"),
    "courier_parcel": ("a courier company", "FedEx / DHL"),
    "investment_stock": ("a stock trading advisor", "investment platform"),
    "lottery_prize": ("a lottery / lucky-draw organizer", "KBC-style scheme"),
    "tech_support": ("Microsoft / Apple support", "tech support"),
    "job_task": ("a part-time job recruiter", "task platform"),
    "loan_app": ("a loan agent", "instant-loan app"),
    "romance": ("an online acquaintance", "romantic partner"),
    "deepfake_voice": ("a family member (cloned voice)", "family member"),
    "upi_collect_request": ("a UPI counterparty", "buyer/seller"),
    "other": ("an unknown sender", "sender"),
    "likely_safe": ("the sender", "sender"),
}


def _guess_impersonated_entity(scam_type: str, text: str) -> str:
    """Try to detect a specific brand/name in the text; else fall back to a
    generic label per scam_type. Text scan uses a small hand-curated list; a
    miss returns the generic label (no fabrication)."""
    text_l = (text or "").lower()
    brands = [
        "cbi", "ed officer", "narcotics", "cyber cell", "mumbai police",
        "sbi", "hdfc", "hdfc bank", "icici", "axis", "kotak", "yes bank",
        "fedex", "dhl", "blue dart", "india post", "indian post",
        "microsoft", "apple", "amazon", "kbc", "jio", "adani", "tata",
    ]
    for b in brands:
        if re.search(rf"\b{re.escape(b)}\b", text_l):
            return b.upper() if len(b) <= 4 else b.title()
    generic = _ENTITY_MAP.get(scam_type) or _ENTITY_MAP["other"]
    return generic[0]


# ---------------------------------------------------------------------------
# Artifact extraction (numbers, UPI IDs, URLs) — best-effort, no fabrication
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_UPI_RE = re.compile(r"\b[a-z0-9._-]{2,}@[a-z]{2,}\b", re.IGNORECASE)
# Phone: 10-digit Indian, or +91 form, or the 4-digit shortcodes we care about
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")


def _extract_contact_hints(text: str) -> dict:
    text = text or ""
    urls = _URL_RE.findall(text)
    upi = _UPI_RE.findall(text)
    phones = _PHONE_RE.findall(text)
    # Dedupe preserving order.
    def _dedup(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen:
                seen.add(x); out.append(x)
        return out
    return {
        "urls": _dedup(urls),
        "upi_ids": _dedup(upi),
        "phones": _dedup(phones),
    }


# ---------------------------------------------------------------------------
# Language-specific summary templates
# ---------------------------------------------------------------------------

_SUMMARIES = {
    "en": {
        "opener": "On [DATE], I received a message/call claiming to be from {entity}.",
        "asked": "It asked me to {ask}.",
        "belief": "I believe this is a {scam_type_human} scam.",
        "payment": "I transferred / was asked to transfer money [AMOUNT] via [UPI/BANK REF].",
        "contact_prefix": "Sender / contact details from the message:",
        "no_contact": "No sender contact details were visible in the message.",
        "personal": "My details: [YOUR NAME], [YOUR PHONE], [YOUR CITY].",
    },
    "hi": {
        "opener": "[तारीख] को मुझे {entity} बनकर एक संदेश/कॉल मिला।",
        "asked": "उसने मुझसे {ask} के लिए कहा।",
        "belief": "मुझे लगता है यह {scam_type_human} घोटाला है।",
        "payment": "मैंने [राशि] रुपये [UPI/बैंक विवरण] के माध्यम से भेजे / भेजने को कहा गया।",
        "contact_prefix": "संदेश में दिखे प्रेषक/संपर्क विवरण:",
        "no_contact": "संदेश में कोई प्रेषक संपर्क विवरण नहीं मिला।",
        "personal": "मेरा विवरण: [आपका नाम], [आपका फ़ोन], [आपका शहर]।",
    },
    "te": {
        "opener": "[తేదీ] న నాకు {entity} నుండి అని చెప్పుకుంటూ ఒక సందేశం/కాల్ వచ్చింది.",
        "asked": "అది నన్ను {ask} చేయమని అడిగింది.",
        "belief": "ఇది {scam_type_human} మోసం అని నేను భావిస్తున్నాను.",
        "payment": "నేను [మొత్తం] రూపాయలు [UPI/బ్యాంక్ వివరాలు] ద్వారా పంపాను / పంపమని అడిగారు.",
        "contact_prefix": "సందేశంలో కనిపించిన పంపినవారి / సంప్రదింపు వివరాలు:",
        "no_contact": "సందేశంలో పంపినవారి సంప్రదింపు వివరాలు కనిపించలేదు.",
        "personal": "నా వివరాలు: [మీ పేరు], [మీ ఫోన్], [మీ నగరం].",
    },
}


# Human-friendly rendering of scam_type in each language.
_TYPE_HUMAN = {
    "digital_arrest": {
        "en": "digital arrest", "hi": "डिजिटल अरेस्ट", "te": "డిజిటల్ అరెస్ట్"},
    "kyc_bank": {
        "en": "KYC / bank verification", "hi": "KYC / बैंक", "te": "KYC / బ్యాంక్"},
    "courier_parcel": {
        "en": "fake courier / customs", "hi": "नकली कूरियर / कस्टम", "te": "నకిలీ కొరియర్ / కస్టమ్స్"},
    "investment_stock": {
        "en": "investment / stock tip", "hi": "निवेश / स्टॉक टिप", "te": "పెట్టుబడి / స్టాక్ టిప్"},
    "lottery_prize": {
        "en": "lottery / prize", "hi": "लॉटरी / इनाम", "te": "లాటరీ / బహుమతి"},
    "tech_support": {
        "en": "fake tech support", "hi": "नकली टेक-सपोर्ट", "te": "నకిలీ టెక్-సపోర్ట్"},
    "job_task": {
        "en": "task / part-time job", "hi": "टास्क / पार्ट-टाइम जॉब", "te": "టాస్క్ / పార్ట్-టైమ్ ఉద్యోగం"},
    "loan_app": {
        "en": "loan-app", "hi": "लोन ऐप", "te": "లోన్ యాప్"},
    "romance": {"en": "romance", "hi": "रोमांस", "te": "రొమాన్స్"},
    "deepfake_voice": {
        "en": "deepfake voice / family emergency", "hi": "डीपफेक वॉइस", "te": "డీప్‌ఫేక్ వాయిస్"},
    "upi_collect_request": {
        "en": "UPI collect-request", "hi": "UPI कलेक्ट-रिक्वेस्ट", "te": "UPI కలెక్ట్-రిక్వెస్ట్"},
    "other": {"en": "suspicious message", "hi": "संदिग्ध संदेश", "te": "అనుమానాస్పద సందేశం"},
}


# "asked to..." action clause, per scam_type + language.
_ASK_CLAUSE = {
    "digital_arrest": {
        "en": "stay on a video call and transfer money to a 'verification account'",
        "hi": "वीडियो कॉल पर बने रहने और 'वेरिफिकेशन खाते' में पैसे भेजने",
        "te": "వీడియో కాల్‌లో ఉండి 'వెరిఫికేషన్ ఖాతా'కు డబ్బు పంపాలని",
    },
    "kyc_bank": {
        "en": "share OTP / click a link to complete KYC",
        "hi": "OTP साझा करने / KYC लिंक पर क्लिक करने",
        # NOTE: the Telugu `asked` template appends " చేయమని అడిగింది." after this
        # fragment, so the fragment itself must NOT end in "చేయమని" — otherwise
        # you get "…చేయమని చేయమని అడిగింది." Kept as a bare noun phrase to slot in
        # cleanly: "అది నన్ను OTP షేర్ / KYC లింక్ క్లిక్ చేయమని అడిగింది."
        "te": "OTP షేర్ / KYC లింక్ క్లిక్",
    },
    "courier_parcel": {
        "en": "pay a customs / clearance fee to release a parcel",
        "hi": "पार्सल छुड़ाने के लिए कस्टम/क्लीयरेंस शुल्क देने",
        "te": "పార్సెల్ విడుదల కోసం కస్టమ్స్/క్లియరెన్స్ ఫీజు చెల్లించమని",
    },
    "investment_stock": {
        "en": "join a trading group / deposit money for guaranteed returns",
        "hi": "ट्रेडिंग ग्रुप जॉइन करने / गारंटीड रिटर्न के लिए पैसे जमा करने",
        "te": "ట్రేడింగ్ గ్రూప్‌లో చేరమని / గ్యారంటీ లాభాల కోసం డబ్బు జమ చేయమని",
    },
    "lottery_prize": {
        "en": "pay a 'processing fee' or share bank details to claim a prize",
        "hi": "इनाम पाने के लिए 'प्रोसेसिंग फीस' देने या बैंक विवरण साझा करने",
        "te": "బహుమతి పొందడానికి 'ప్రాసెసింగ్ ఫీజు' చెల్లించమని లేదా బ్యాంక్ వివరాలు షేర్ చేయమని",
    },
    "tech_support": {
        "en": "install remote-access software and share verification codes",
        "hi": "रिमोट-एक्सेस सॉफ्टवेयर इंस्टॉल करने और वेरिफिकेशन कोड साझा करने",
        "te": "రిమోట్-యాక్సెస్ సాఫ్ట్‌వేర్ ఇన్‌స్టాల్ చేయమని మరియు వెరిఫికేషన్ కోడ్‌లను షేర్ చేయమని",
    },
    "job_task": {
        "en": "pay a 'prepaid task' fee to earn higher commissions",
        "hi": "अधिक कमाई के लिए 'प्रीपेड टास्क' शुल्क देने",
        "te": "ఎక్కువ సంపాదన కోసం 'ప్రీపెయిడ్ టాస్క్' ఫీజు చెల్లించమని",
    },
    "loan_app": {
        "en": "pay an upfront processing fee to receive a loan",
        "hi": "लोन पाने के लिए अग्रिम प्रोसेसिंग शुल्क देने",
        "te": "రుణం పొందడానికి ముందస్తు ప్రాసెసింగ్ ఫీజు చెల్లించమని",
    },
    "romance": {
        "en": "send money for an emergency (airport / customs / hospital)",
        "hi": "आपात स्थिति (हवाई अड्डा/कस्टम/अस्पताल) के लिए पैसे भेजने",
        "te": "అత్యవసరం (విమానాశ్రయం/కస్టమ్స్/హాస్పిటల్) కోసం డబ్బు పంపాలని",
    },
    "deepfake_voice": {
        "en": "urgently transfer money because a family member is 'in trouble'",
        "hi": "'परिवार के सदस्य की मुसीबत' के नाम पर तुरंत पैसे भेजने",
        "te": "'కుటుంబ సభ్యుడు కష్టంలో ఉన్నారు' అనే పేరుతో వెంటనే డబ్బు పంపమని",
    },
    "upi_collect_request": {
        "en": "approve a UPI collect-request / enter my UPI PIN to 'receive' money",
        "hi": "पैसे 'प्राप्त' करने के लिए UPI कलेक्ट-रिक्वेस्ट अप्रूव करने / UPI PIN डालने",
        "te": "డబ్బు 'అందుకోవడానికి' UPI కలెక్ట్-రిక్వెస్ట్ ఆమోదించమని / UPI PIN నమోదు చేయమని",
    },
    "other": {
        "en": "share sensitive information or make an urgent payment",
        "hi": "संवेदनशील जानकारी साझा करने या तुरंत भुगतान करने",
        "te": "సున్నితమైన సమాచారాన్ని షేర్ చేయమని లేదా వెంటనే చెల్లించమని",
    },
}


# ---------------------------------------------------------------------------
# Evidence checklist per scam_type
# ---------------------------------------------------------------------------

_EVIDENCE = {
    "digital_arrest": [
        "Screenshot / screen recording of the video call and any on-screen 'officer' badge",
        "Caller's phone number and any Skype ID / WhatsApp handle they used",
        "Any bank account, IFSC, or UPI ID they gave you for the 'verification' transfer",
        "Screenshots of every message and any 'notice' image they sent",
        "If money was transferred: the transaction ID, amount, date, time, and your bank statement",
    ],
    "kyc_bank": [
        "Screenshot of the SMS / WhatsApp message including the full link",
        "The exact URL you were sent to (do NOT open it again)",
        "The sender's phone number or short-code (e.g. VD-HDFCBK)",
        "If you clicked the link or entered any details: what you entered and when",
        "Bank account number the request referred to (last 4 digits only for your safety)",
    ],
    "courier_parcel": [
        "Screenshot of the message / recording of the call",
        "Any 'tracking number', 'waybill', or reference the sender gave",
        "The bank account / UPI ID the sender demanded payment to",
        "The claimed courier company (FedEx / DHL / India Post) so the real courier can be alerted",
        "If money was transferred: transaction ID, amount, and your bank statement",
    ],
    "investment_stock": [
        "Screenshots of the WhatsApp / Telegram group and its admin(s)",
        "Group / channel invite link",
        "Screenshots of the app or website used and its URL",
        "UPI IDs / bank accounts you were asked to deposit to",
        "If deposited: every transaction ID, amount, and your bank statement",
    ],
    "lottery_prize": [
        "Screenshot of the winning-notice message with the full sender details",
        "Any 'claim form' or link you were asked to fill in",
        "Bank / UPI details demanded as 'processing fee' or 'GST'",
        "Any Aadhaar / PAN images you may have sent (report if you did)",
    ],
    "tech_support": [
        "Number that called you and the exact company name they claimed",
        "Name of any remote-access tool you were asked to install (AnyDesk, TeamViewer, etc.)",
        "If you installed it: uninstall it now, then screenshot the install date/time",
        "Any codes, passwords, or card details you shared",
        "If money was moved from your bank/card: transaction IDs and statement",
    ],
    "job_task": [
        "Screenshot of the WhatsApp / Telegram group and its admin",
        "Every task-payment message and the UPI IDs used",
        "If you paid a 'prepaid task' fee: transaction IDs, amounts, dates",
        "The name of the platform / brand impersonated (Amazon, YouTube, etc.)",
    ],
    "loan_app": [
        "The exact loan-app name and Play Store / APK link",
        "Screenshots of the loan-approval message and processing-fee demand",
        "UPI ID / bank account the fee was asked to be paid to",
        "If paid: transaction ID, amount, and your bank statement",
    ],
    "romance": [
        "The dating app / social platform profile URL and screenshots of the profile",
        "The full chat history (export from the app)",
        "Every UPI ID / bank account you were asked to send money to",
        "Every transaction ID, amount, and date if money was sent",
    ],
    "deepfake_voice": [
        "The audio file / voice note itself (do NOT delete)",
        "The number or app account the message came from",
        "Any UPI ID / bank account the sender asked you to pay",
        "If money was sent: transaction ID, amount, timestamp",
    ],
    "upi_collect_request": [
        "Screenshot of the UPI collect-request (with the amount and requester's UPI ID)",
        "The counterparty's phone number and platform they contacted you on",
        "If you approved: transaction ID and screenshot of the debit from your account",
    ],
    "other": [
        "Screenshot of the full message including sender number / UPI ID",
        "Any URL(s) present in the message",
        "If you replied or paid: what you sent and when",
    ],
    "likely_safe": [
        "If you still want to report the number as suspicious, keep a screenshot of the message and the sender number.",
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_REPORTABLE_THRESHOLD = 40


def _base_channels(scam_type: str) -> list[dict]:
    # For likely_safe we still surface Chakshu (users often want to block the
    # number), but drop the police helpline.
    if scam_type == "likely_safe":
        return [_CH_CHAKSHU]
    return [_CH_1930, _CH_PORTAL, _CH_CHAKSHU]


def _pick_urgency(scam_type: str, risk: int, signals: list) -> str:
    if scam_type == "likely_safe":
        return "none"
    signals = signals or []
    if "payment" in signals or risk >= 85:
        return "immediate"
    return "standard"


def _build_summary(
    scam_type: str,
    detected_language: str,
    original_text: str,
    hints: dict,
) -> str:
    lang = detected_language if detected_language in _SUMMARIES else "en"
    t = _SUMMARIES[lang]
    entity = _guess_impersonated_entity(scam_type, original_text)
    scam_human = (_TYPE_HUMAN.get(scam_type) or _TYPE_HUMAN["other"]).get(lang, scam_type)
    ask = (_ASK_CLAUSE.get(scam_type) or _ASK_CLAUSE["other"]).get(lang, "")

    parts: list[str] = []
    parts.append(t["opener"].format(entity=entity))
    if ask:
        parts.append(t["asked"].format(ask=ask))
    parts.append(t["belief"].format(scam_type_human=scam_human))

    # Payment clause: only include when the engine or the text signal it.
    if "payment" in (hints.get("_signals") or []) or hints.get("_risk", 0) >= 85:
        parts.append(t["payment"])

    contact_bits: list[str] = []
    if hints["phones"]:
        contact_bits.append("phone: " + ", ".join(hints["phones"]))
    if hints["upi_ids"]:
        contact_bits.append("UPI: " + ", ".join(hints["upi_ids"]))
    if hints["urls"]:
        contact_bits.append("link(s): " + ", ".join(hints["urls"]))
    if contact_bits:
        parts.append(t["contact_prefix"] + " " + "; ".join(contact_bits) + ".")
    else:
        parts.append(t["no_contact"])

    parts.append(t["personal"])
    return " ".join(parts)


def build_report(verdict: dict, original_text: str) -> dict:
    """Build the guided-reporting package.

    Never raises. On any unexpected input returns a minimal safe report.
    Reads from `verdict` and `original_text`; never contacts an external
    service and never mutates its inputs.
    """
    try:
        scam_type = str(verdict.get("scam_type") or "other")
        risk = int(verdict.get("risk") or 0)
        signals = list(verdict.get("signals") or [])
        detected_language = str(verdict.get("detected_language") or "en")

        should_report = scam_type != "likely_safe" and risk >= _REPORTABLE_THRESHOLD
        urgency = _pick_urgency(scam_type, risk, signals)
        channels = _base_channels(scam_type)

        checklist = list(
            _EVIDENCE.get(scam_type) or _EVIDENCE["other"]
        )

        if should_report:
            hints = _extract_contact_hints(original_text)
            hints["_signals"] = signals
            hints["_risk"] = risk
            summary = _build_summary(scam_type, detected_language, original_text, hints)
        else:
            summary = ""
            # For likely_safe leave a short reassurance in the language.
            # (No push to file a police complaint.)

        return {
            "should_report": should_report,
            "urgency": urgency,
            "channels": channels,
            "prefilled_summary": summary,
            "evidence_checklist": checklist,
            "language": detected_language,
        }
    except Exception as e:  # pragma: no cover - defensive
        log.warning("report.build_report failed silently: %s", e)
        risk = 0
        try:
            risk = int(verdict.get("risk") or 0)
        except Exception:
            pass
        scam_type = str((verdict or {}).get("scam_type") or "other")
        should_report = scam_type != "likely_safe" and risk >= _REPORTABLE_THRESHOLD
        return {
            "should_report": should_report,
            "urgency": "standard" if should_report else "none",
            "channels": _base_channels(scam_type),
            "prefilled_summary": "",
            "evidence_checklist": _EVIDENCE["other"],
            "language": str((verdict or {}).get("detected_language") or "en"),
        }


# Legacy stub name kept for callers that may still import it.
def build_report_stub(*args, **kwargs) -> dict:  # pragma: no cover
    raise NotImplementedError("use build_report(verdict, original_text)")
