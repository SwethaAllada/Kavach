"""Guided fraud-reporting package builder.

Given a finalized verdict + the original message, produces a paste-ready
complaint description, an ordered list of official Indian reporting channels,
and a scam-type-specific evidence checklist. Never submits anything anywhere.

Design constraints:
  - Language-aware: prefilled_summary is written in verdict.detected_language
    (see core.locales_loader.SUPPORTED_LANGUAGES), falling back to English.
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

from core.locales_loader import get_string

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
# Chakshu form category mapping
# ---------------------------------------------------------------------------

# Maps each SCAM_TAXONOMY value to the exact category string used by the
# Chakshu (Sanchar Saathi) complaint form, so the frontend can tell the user
# exactly which dropdown option to pick. likely_safe maps to None: no
# Chakshu report is warranted for a message the engine assessed as safe.
CHAKSHU_CATEGORY_MAP: dict[str, Optional[str]] = {
    "digital_arrest": "Impersonation as Police, CBI, Customs, Aadhaar, RBI etc",
    "kyc_bank": "KYC and Payment related to Bank / Electricity / Gas / Insurance etc",
    "investment_stock": "Investment, Stock Market and Trading",
    "tech_support": "Fake Customer Care Helpline",
    "job_task": "Online job / lottery / gifts / loan offers",
    "lottery_prize": "Online job / lottery / gifts / loan offers",
    "loan_app": "Online job / lottery / gifts / loan offers",
    "courier_parcel": "Impersonation as Police, CBI, Customs, Aadhaar, RBI etc",
    "upi_collect_request": "KYC and Payment related to Bank / Electricity / Gas / Insurance etc",
    "romance": "Impersonation as a relative / friend",
    "deepfake_voice": "Impersonation as Police, CBI, Customs, Aadhaar, RBI etc",
    "other": "Any Other Suspected Fraud",
    "likely_safe": None,
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
# Language-specific summary templates (summary_parts, type_human, ask_clause)
# now live in locales/<lang>/responses.yaml under `report`, read via
# core.locales_loader.get_string() — see _build_summary() below. Each key is
# looked up independently, so a locale missing just one key (e.g. ask_clause
# for a given scam_type) falls back to English for that key alone rather
# than failing the whole summary.
# ---------------------------------------------------------------------------

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


# Hardcoded English backstops for _build_summary's get_string() calls — the
# ultimate fallback if locales/ itself is missing/broken, so a summary is
# always producible. Each summary_parts key falls back independently:
# requested language -> English -> this literal.
_SUMMARY_PART_DEFAULTS = {
    "opener": "On [DATE], I received a message/call claiming to be from {entity}.",
    "asked": "It asked me to {ask}.",
    "belief": "I believe this is a {scam_type_human} scam.",
    "payment": "I transferred / was asked to transfer money [AMOUNT] via [UPI/BANK REF].",
    "contact_prefix": "Sender / contact details from the message:",
    "no_contact": "No sender contact details were visible in the message.",
    "personal": "My details: [YOUR NAME], [YOUR PHONE], [YOUR CITY].",
}


def _summary_part(lang: str, key: str) -> str:
    return get_string(lang, "report", "summary_parts", key, default=_SUMMARY_PART_DEFAULTS[key])


def _build_summary(
    scam_type: str,
    detected_language: str,
    original_text: str,
    hints: dict,
) -> str:
    lang = detected_language
    entity = _guess_impersonated_entity(scam_type, original_text)
    scam_human = get_string(lang, "report", "type_human", scam_type, default=scam_type)
    ask = get_string(lang, "report", "ask_clause", scam_type, default="")

    parts: list[str] = []
    parts.append(_summary_part(lang, "opener").format(entity=entity))
    if ask:
        parts.append(_summary_part(lang, "asked").format(ask=ask))
    parts.append(_summary_part(lang, "belief").format(scam_type_human=scam_human))

    # Payment clause: only include when the engine or the text signal it.
    if "payment" in (hints.get("_signals") or []) or hints.get("_risk", 0) >= 85:
        parts.append(_summary_part(lang, "payment"))

    contact_bits: list[str] = []
    if hints["phones"]:
        contact_bits.append("phone: " + ", ".join(hints["phones"]))
    if hints["upi_ids"]:
        contact_bits.append("UPI: " + ", ".join(hints["upi_ids"]))
    if hints["urls"]:
        contact_bits.append("link(s): " + ", ".join(hints["urls"]))
    if contact_bits:
        parts.append(_summary_part(lang, "contact_prefix") + " " + "; ".join(contact_bits) + ".")
    else:
        parts.append(_summary_part(lang, "no_contact"))

    parts.append(_summary_part(lang, "personal"))
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
            "chakshu_category": CHAKSHU_CATEGORY_MAP.get(scam_type),
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
            "chakshu_category": CHAKSHU_CATEGORY_MAP.get(scam_type),
        }


# Legacy stub name kept for callers that may still import it.
def build_report_stub(*args, **kwargs) -> dict:  # pragma: no cover
    raise NotImplementedError("use build_report(verdict, original_text)")
