"""Deterministic rules-based prior classifier.

Runs with zero external calls, never raises. Provides both:
  - A fast prior for the LLM fusion step.
  - A complete fallback classification when the LLM is unavailable.

Pattern lists intentionally cover English, Hindi (Devanagari + Hinglish),
and Telugu (Telugu script + Tenglish). Extend by adding to the dicts below.
"""

from __future__ import annotations

import re
from typing import Iterable

SCAM_TAXONOMY: list[str] = [
    "digital_arrest",
    "investment_stock",
    "kyc_bank",
    "courier_parcel",
    "job_task",
    "loan_app",
    "lottery_prize",
    "tech_support",
    "upi_collect_request",
    "romance",
    "deepfake_voice",
    "other",
    "likely_safe",
]

SIGNALS: list[str] = [
    "authority",
    "fear",
    "isolation",
    "urgency",
    "payment",
    "secrecy",
    "too_good_to_be_true",
    "credential_request",
]


# Per-scam_type keyword/regex patterns. Keep readable, extend freely.
# Matching is case-insensitive over the full text.
SCAM_PATTERNS: dict[str, list[str]] = {
    "digital_arrest": [
        r"digital\s*arrest",
        r"arrest\s*warrant",
        r"cbi\b",
        r"\bed\s*(?:officer|department)\b",
        r"narcotics",
        r"cyber\s*cell",
        r"court\s*(?:notice|summon)",
        r"skype\s*(?:call|verification)",
        r"video\s*(?:call|verification).*(?:police|officer)",
        r"मुकदमा",
        r"गिरफ्तार",
        r"वारंट",
        r"పోలీస్.*కేసు",
        r"అరెస్ట్",
        r"warrant\s*jaari",
        r"arrest\s*ho\s*jayega",
    ],
    "investment_stock": [
        r"guaranteed\s*return",
        r"double\s*your\s*(?:money|investment)",
        r"stock\s*tip",
        r"ipo\s*allotment",
        r"pump\s*and\s*dump",
        r"telegram\s*(?:group|channel).*(?:profit|trading|stock)",
        r"vip\s*(?:signal|group)",
        r"निवेश.*गारंटी",
        r"పెట్టుబడి.*గ్యారంటీ",
        r"guaranteed\s*profit",
    ],
    "kyc_bank": [
        r"kyc\s*(?:update|pending|expire|verification)",
        r"account\s*(?:will\s*be\s*)?(?:blocked|suspended|freeze[d]?)",
        r"pan\s*(?:card\s*)?(?:link|update)",
        r"aadha?ar\s*(?:link|verification|update)",
        r"verify\s*your\s*account",
        r"netbanking\s*(?:suspend|block)",
        r"खाता\s*बंद",
        r"केवाईसी",
        r"ఖాతా.*బ్లాక్",
        r"kyc\s*cheyandi",
        r"account\s*band",
    ],
    "courier_parcel": [
        r"parcel\s*(?:held|stuck|seized|contains)",
        r"customs\s*(?:clearance|duty|hold)",
        r"fedex.*(?:package|parcel|shipment).*(?:illegal|drug|seize)",
        r"dhl.*(?:package|hold)",
        r"blue\s*dart.*(?:hold|clearance)",
        r"पार्सल.*(?:रोक|जब्त)",
        r"పార్సెల్.*(?:ఆపార|కస్టమ్స్)",
    ],
    "job_task": [
        r"work\s*from\s*home.*(?:daily|earn)\s*\d",
        r"part[-\s]*time\s*job.*(?:earn|salary).*\d",
        r"like\s*and\s*subscribe.*(?:earn|paid|salary)",
        r"telegram.*task.*(?:earn|paid)",
        r"prepaid\s*task",
        r"rating\s*task.*earn",
        r"घर\s*बैठे\s*(?:कमाई|कमाओ)",
        r"ఇంటి\s*నుండి.*సంపాదన",
    ],
    "loan_app": [
        r"instant\s*loan.*no\s*(?:documents|papers|cibil)",
        r"loan\s*approved.*(?:processing|advance)\s*fee",
        r"pre[-\s]*approved\s*loan.*click",
        r"तुरंत\s*लोन",
        r"వెంటనే\s*రుణం",
    ],
    "lottery_prize": [
        r"you\s*(?:have\s*)?won",
        r"lottery\s*(?:winner|prize)",
        r"lucky\s*draw",
        r"kbc\s*(?:lottery|winner)",
        r"congratulations.*(?:selected|winner|prize)",
        r"आपने\s*जीता",
        r"లాటరీ\s*గెలిచారు",
    ],
    "tech_support": [
        r"microsoft\s*(?:support|technician|security)",
        r"your\s*(?:computer|pc|device)\s*is\s*infected",
        r"virus\s*(?:detected|alert).*call",
        r"windows\s*(?:license|activation).*expire",
        r"remote\s*(?:desktop|access).*(?:install|download)",
        r"anydesk|team\s*viewer.*(?:install|download)",
    ],
    "upi_collect_request": [
        r"upi\s*(?:collect|request)",
        r"gpay.*request",
        r"phonepe.*request.*(?:pay|approve)",
        r"scan.*qr.*(?:receive|refund)",
        r"refund.*scan.*qr",
        r"approve\s*(?:the\s*)?request.*receive",
    ],
    "romance": [
        r"i\s*love\s*you.*(?:send|money|help)",
        r"stuck\s*(?:in|at)\s*airport.*(?:money|help)",
        r"gift.*customs.*(?:pay|clear)",
        r"military.*deployed.*(?:money|help)",
    ],
    "deepfake_voice": [
        r"(?:mummy|papa|beta|son|daughter).*(?:kidnap|accident|hospital).*(?:money|pay|send)",
        r"voice\s*(?:message|note).*urgent.*money",
    ],
}


# Per-signal keyword/regex patterns.
SIGNAL_PATTERNS: dict[str, list[str]] = {
    "authority": [
        r"\b(?:police|cbi|ed|income\s*tax|customs|rbi|trai|court|judge|officer|inspector)\b",
        r"पुलिस|अदालत|अधिकारी",
        r"పోలీస్|కోర్టు|అధికారి",
    ],
    "fear": [
        r"\b(?:arrest|jail|fir|case\s*filed|legal\s*action|penalty|fine)\b",
        r"account\s*(?:will\s*be\s*)?(?:blocked|suspend|freeze)",
        r"जेल|गिरफ्तार|कानूनी",
        r"జైలు|అరెస్ట్|చట్టపరమైన",
    ],
    "isolation": [
        r"do\s*not\s*(?:tell|inform|share).*(?:family|friends)",
        r"stay\s*on\s*(?:the\s*)?(?:call|line)",
        r"don'?t\s*(?:hang\s*up|disconnect)",
        r"किसी\s*को\s*(?:मत\s*बताना|मत\s*बताएं)",
        r"ఎవరికీ\s*చెప్పకండి",
    ],
    "urgency": [
        r"\b(?:immediately|urgent|right\s*now|within\s*\d+\s*(?:minutes?|hours?))\b",
        r"last\s*(?:chance|warning)",
        r"expires?\s*(?:today|now|soon)",
        r"तुरंत|अभी|आज\s*ही",
        r"వెంటనే|ఇప్పుడే|ఈరోజే",
    ],
    "payment": [
        r"\b(?:pay|transfer|deposit|remit|send\s*money)\b",
        r"upi|imps|neft|rtgs|bank\s*transfer",
        r"₹\s*\d|rs\.?\s*\d|inr\s*\d",
        r"भुगतान|पैसे\s*भेज",
        r"చెల్లించండి|డబ్బు\s*పంపండి",
    ],
    "secrecy": [
        r"confidential|classified|between\s*(?:you\s*and\s*me|us)",
        r"do\s*not\s*(?:disclose|share)\s*this\s*(?:with|from)\s*(?:anyone|your\s*family|the\s*bank|police)",
        r"गुप्त|राज़",
        r"రహస్యం",
    ],
    "too_good_to_be_true": [
        r"guaranteed",
        r"100%\s*(?:profit|return|safe)",
        r"free\s*(?:gift|iphone|cash)",
        r"double\s*(?:money|return)",
        r"मुफ्त",
        r"ఉచితం",
    ],
    "credential_request": [
        r"\botp\b",
        r"one[-\s]*time\s*password",
        r"share\s*(?:your\s*)?(?:otp|pin|password|cvv)",
        r"cvv|atm\s*pin",
        r"otp\s*(?:share|batao|cheyandi|bhejo)",
        r"पासवर्ड|ओटीपी",
        r"పాస్‌వర్డ్|ఓటీపీ",
    ],
}


def _find_matches(text: str, patterns: Iterable[str]) -> list[str]:
    found: list[str] = []
    for pat in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE | re.UNICODE)
        if m:
            found.append(m.group(0))
    return found


# ---------------------------------------------------------------------------
# Negative evidence: patterns that make a message LESS likely to be a scam.
#
# These only ever SUBTRACT from rule_risk (see rules_classify below) — they
# never force scam_type to likely_safe and never delete a matched signal.
# The rules prior is one input to classifier._fuse(); a lower prior lets the
# LLM and RAG still override if the message is actually a scam wearing a
# legit disguise. This mirrors the RAG safe-lock discipline in
# classifier.py: nudge, don't decide.
#
# Each entry is (regex, points). Points are summed and the total is capped
# by _NEGATIVE_EVIDENCE_CAP before being subtracted from rule_risk.
# ---------------------------------------------------------------------------

# The defining distinction for OTP messages is WHO is asked to act:
#   - legit: the message informs the user of an OTP and instructs THEM not
#     to share it with anyone else (a warning about the user's own future
#     behavior).
#   - scam: the message asks the user to hand the OTP TO THE SENDER (an
#     "executive", "officer", "team", or unspecified "us") right now.
# `_OTP_HARVEST_RE` is checked first and unconditionally suppresses the
# negative-evidence nudge if it matches, so a scam message that pastes both
# phrases ("share your OTP... but also never share your OTP!") to game this
# heuristic still scores as risky.
_OTP_HARVEST_RE = re.compile(
    r"(?:share|read\s*out|tell|give|provide)\s*(?:the|your|this)?\s*otp"
    r"\s*(?:to|with)\s*(?:our|the|any)?\s*(?:executive|officer|agent|team|"
    r"representative|us|customer\s*care|support)",
    re.IGNORECASE,
)

_NEGATIVE_PATTERNS: list[tuple[re.Pattern, int]] = [
    # "NEVER share this OTP with anyone" / "do not share this OTP with
    # anyone" — an advisory aimed at the user's own future behavior, not a
    # request for the user to hand over anything now.
    (
        re.compile(
            r"(?:never|do\s*not|don'?t)\s*share\s*(?:this|your|the)?\s*otp"
            r".{0,30}with\s*anyone",
            re.IGNORECASE,
        ),
        15,
    ),
    (re.compile(r"साझा\s*न\s*करें", re.IGNORECASE), 15),
    # "Bank will never call and ask for this OTP" — the message itself
    # states the anti-scam rule, which is the opposite of a scammer asking
    # for the OTP.
    (
        re.compile(
            r"bank\s*will\s*never\s*(?:call|ask)", re.IGNORECASE
        ),
        15,
    ),
    # Informational transaction/security alert that tells the user to call
    # a support line THEMSELVES if something looks wrong — contrasts with a
    # scam's "click this link" / "approve this request" / "pay this fee".
    (
        re.compile(
            r"if\s*this\s*(?:transaction\s*)?wasn'?t\s*you.{0,40}"
            r"(?:call|visit)|"
            r"call\s*[\d\-\s]{6,}\s*immediately\s*if\s*this",
            re.IGNORECASE,
        ),
        12,
    ),
    # KYC / bill reminders that point to the bank's OWN official app or
    # branch, with no link and no OTP/PIN/credential request — contrasts
    # with a scam KYC message's "click this link to verify" / "share OTP".
    (
        re.compile(
            r"(?:visit\s*(?:your\s*)?(?:home\s*)?branch|official\s*"
            r"(?:app|mobile\s*app|website))",
            re.IGNORECASE,
        ),
        10,
    ),
]

_NEGATIVE_EVIDENCE_CAP = 30


def _negative_evidence_score(text: str) -> int:
    """Sum bounded negative-evidence points. Never applied if the message
    also contains an explicit OTP-harvesting ask (see _OTP_HARVEST_RE)."""
    if _OTP_HARVEST_RE.search(text):
        return 0
    total = 0
    for pattern, points in _NEGATIVE_PATTERNS:
        if pattern.search(text):
            total += points
    return min(total, _NEGATIVE_EVIDENCE_CAP)


def rules_classify(text: str) -> dict:
    """Classify text using deterministic rules only. Never raises."""
    if not isinstance(text, str):
        text = str(text or "")

    matched_keywords: list[str] = []

    scam_hits: dict[str, int] = {}
    for scam_type, patterns in SCAM_PATTERNS.items():
        hits = _find_matches(text, patterns)
        if hits:
            scam_hits[scam_type] = len(hits)
            matched_keywords.extend(hits)

    matched_signals: list[str] = []
    for signal, patterns in SIGNAL_PATTERNS.items():
        hits = _find_matches(text, patterns)
        if hits:
            matched_signals.append(signal)
            matched_keywords.extend(hits)

    if scam_hits:
        best_scam = max(scam_hits.items(), key=lambda kv: kv[1])[0]
    elif matched_signals:
        best_scam = "other"
    else:
        best_scam = "likely_safe"

    # Coarse risk: signals contribute, top scam-type hits contribute more.
    signal_score = min(len(matched_signals) * 12, 60)
    scam_score = min(sum(scam_hits.values()) * 15, 60)
    if best_scam == "likely_safe":
        rule_risk = max(0, signal_score - 20)
    else:
        rule_risk = min(100, 20 + signal_score + scam_score)

    # Negative evidence only ever lowers the prior — it never changes
    # scam_type and never removes a matched signal (matched_keywords /
    # matched_signals are left intact so callers can still see why the
    # positive signals fired).
    rule_risk = max(0, rule_risk - _negative_evidence_score(text))

    return {
        "scam_type": best_scam,
        "signals": matched_signals,
        "rule_risk": rule_risk,
        "matched_keywords": matched_keywords,
    }


def apply_rules(text: str) -> dict:
    """Public alias kept for backwards compatibility with earlier stub."""
    return rules_classify(text)
