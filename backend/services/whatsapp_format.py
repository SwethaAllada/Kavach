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

from core.locales_loader import SUPPORTED_LANGUAGES, get_string
from core.locales_loader import _translate_safely  # reuse existing translate-on-demand path

# Twilio SMS is 1600 chars; WhatsApp is 4096 but many carriers render only the
# first ~1500 cleanly. We target 1500 as a safe hard cap.
MAX_MESSAGE_CHARS = 1500

# Human-readable scam-type labels and fixed WhatsApp-reply sentences (brand,
# headline verdict lines, section labels) now live in
# locales/<lang>/responses.yaml under `whatsapp.scam_labels` /
# `whatsapp.strings`, read via core.locales_loader.get_string(). Each lookup
# falls back independently: requested language -> English -> the literal
# default given at the call site, so a locale missing one string can't break
# the reply — see _whatsapp_string() / _scam_label() below.

# Hardcoded English backstops — the ultimate fallback if locales/ itself is
# missing/broken, so a WhatsApp reply can always be produced.
_WHATSAPP_STRING_DEFAULTS = {
    "brand": "Kavach",
    "scam": "⚠️ LIKELY SCAM",
    "caution": "⚠️ Suspicious — be careful",
    "safe": "✅ Looks safe",
    "risk_line": "{headline} — {label} (risk {risk}/100)",
    "why": "Why:",
    "action": "What to do:",
    "report_prefix": "Report now:",
    "summary_available": "A ready-to-file complaint summary is available in the Kavach app.",
    "footer": "— Kavach (guidance only; we never file for you)",
    "err": "Sorry, we couldn't analyze that message just now. Please try again in a moment.",
}


def _lang(verdict: dict) -> str:
    lang = str((verdict or {}).get("detected_language") or "en")
    return lang if lang in SUPPORTED_LANGUAGES else "en"


def _whatsapp_string(lang: str, key: str) -> str:
    return get_string(lang, "whatsapp", "strings", key, default=_WHATSAPP_STRING_DEFAULTS[key])


def _scam_label(scam_type: str, lang: str) -> str:
    return get_string(lang, "whatsapp", "scam_labels", scam_type, default=scam_type)


def _headline(scam_type: str, risk: int, lang: str) -> str:
    if scam_type == "likely_safe" or risk < 40:
        return _whatsapp_string(lang, "safe")
    if risk < 70:
        return _whatsapp_string(lang, "caution")
    return _whatsapp_string(lang, "scam")


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
    prefix = _whatsapp_string(lang, "report_prefix")
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
            return _whatsapp_string("en", "err")

        lang = _lang(verdict)
        scam_type = str(verdict.get("scam_type") or "other")
        risk = int(verdict.get("risk") or 0)

        parts: list[str] = []

        # Line 1 — brand + risk headline (large, scannable).
        headline = _headline(scam_type, risk, lang)
        label = _scam_label(scam_type, lang)
        parts.append(
            _whatsapp_string(lang, "risk_line").format(headline=headline, label=label, risk=risk)
        )

        # Section: why (from the verdict's explanation).
        explanation = str(verdict.get("explanation") or "").strip()
        if explanation:
            parts.append("")
            parts.append(f"{_whatsapp_string(lang, 'why')} {explanation}")

        # Section: what to do (from the verdict's recommended_action).
        action = str(verdict.get("recommended_action") or "").strip()
        if action:
            parts.append("")
            parts.append(f"{_whatsapp_string(lang, 'action')} {action}")

        # Reporting block — only if the engine says should_report.
        channel_line = _top_channel_line(verdict, lang)
        if channel_line:
            parts.append("")
            parts.append(channel_line)
            parts.append(_whatsapp_string(lang, "summary_available"))

        # Footer keeps expectations honest (guidance only).
        parts.append("")
        parts.append(_whatsapp_string(lang, "footer"))

        # Conversational follow-up menu — only for a SCAM verdict (see
        # is_scam_verdict()), so a safe/caution message doesn't get pestered
        # with reporting options.
        if is_scam_verdict(scam_type, risk):
            parts.append("")
            parts.append(followup_menu_text(lang))

        body = "\n".join(parts)
        return _clip(body, MAX_MESSAGE_CHARS)
    except Exception:
        # Never let a formatting bug surface as a 500 to Twilio.
        return _whatsapp_string("en", "err")


# ---------------------------------------------------------------------------
# Conversational follow-up flow (stateless state machine)
#
# After a SCAM verdict, verdict_to_whatsapp_text() appends a numbered menu.
# webhook.py intercepts a handful of short bare-keyword replies (see
# match_followup_keyword()) BEFORE calling the classification engine, and
# renders one of the templated replies below instead. No LLM calls, no
# session store — WhatsApp is stateless, so we don't know which prior verdict
# a keyword reply refers to; the templates below are written to be useful
# without that context (see module docstring additions and CLAUDE.md task
# notes for the reasoning).
# ---------------------------------------------------------------------------

_SCAM_RISK_THRESHOLD = 60


def is_scam_verdict(scam_type: str, risk: int) -> bool:
    """True when a verdict warrants the follow-up menu: not likely_safe and
    risk >= _SCAM_RISK_THRESHOLD."""
    return scam_type != "likely_safe" and risk >= _SCAM_RISK_THRESHOLD


# Cache of translated follow-up template strings, separate from
# locales_loader's own cache since these strings have no YAML path — keyed by
# (lang, template_key) -> translated string.
_followup_translation_cache: dict[tuple[str, str], str] = {}


def _translate_template(lang: str, key: str, english_text: str) -> str:
    """Return `english_text` translated to `lang`, cached per (lang, key) for
    the process lifetime. Falls back to the English original on any
    translation failure — mirrors core.locales_loader's translate-on-demand
    behavior for locale-file-backed strings, applied here to the follow-up
    templates that have no locales/ YAML entry."""
    if lang == "en" or lang not in SUPPORTED_LANGUAGES:
        return english_text
    cache_key = (lang, key)
    cached = _followup_translation_cache.get(cache_key)
    if cached is not None:
        return cached
    translated = _translate_safely(english_text, lang)
    result = translated if translated is not None else english_text
    _followup_translation_cache[cache_key] = result
    return result


_FOLLOWUP_MENU_EN = (
    "Reply with a number:\n"
    "1 — I haven't lost money yet, help me report\n"
    "2 — I already transferred money, what do I do\n"
    "3 — I'm not sure, tell me more about this scam"
)

_REPORTING_GUIDANCE_EN = (
    "✅ Good — here's how to report to Chakshu:\n\n"
    "Category: Any Other Suspected Fraud (please verify this matches your case)\n"
    "Complaint text: copy this ↓\n"
    "On [DATE], I received a suspicious message/call of type [TYPE]. "
    "Amount involved (if any): [AMOUNT]. I am reporting this as a suspected fraud.\n\n"
    "Open form: https://sancharsaathi.gov.in/sfc/Home/sfc-complaint.jsp\n\n"
    "Note: For a more specific report, forward your suspicious message first, then reply 1.\n\n"
    "Did you take a screenshot of the message? Reply YES or NO"
)

_EMERGENCY_GUIDANCE_EN = (
    "🚨 Call 1930 RIGHT NOW — this is India's 24/7 cyber crime helpline.\n"
    "Every minute matters when money has been transferred.\n\n"
    "Also do this immediately:\n"
    "1. Call your bank to reverse the transfer if possible\n"
    "2. File at cybercrime.gov.in\n"
    "3. Keep all screenshots as evidence\n\n"
    "Reply HELP for more options."
)

_CONFIRMATION_EN = (
    "✅ Great. Attach it to the Chakshu form under 'Attach a screenshot'.\n"
    "Your report is fully prepared. Stay safe — you did the right thing by "
    "checking. Reply HELP if you need anything else."
)

_ALTERNATIVE_EN = (
    "No problem. If possible, take a screenshot before deleting the message "
    "— it helps authorities trace the scammer. Reply HELP for more options."
)

_HELP_MENU_EN = (
    "Kavach — what can I help you with?\n\n"
    "Reply:\n"
    "1 — Report this scam to Chakshu\n"
    "2 — I lost money — emergency steps\n"
    "3 — Learn about this type of scam\n"
    "ANALYZE — Check a new message"
)

# Plain-language "how this scam works / what NOT to do" explanations, one per
# services.rules.SCAM_TAXONOMY value. Used by education_text() for the "3"
# follow-up keyword. Deliberately duplicated here rather than imported from
# report.py's _TYPE_HUMAN/_ASK_CLAUSE — those are written for complaint-form
# prose, not a stand-alone explanation a worried user reads on WhatsApp.
SCAM_EDUCATION: dict[str, str] = {
    "digital_arrest": (
        "A digital arrest scam pretends to be CBI, police, or customs. They "
        "create fear of arrest to isolate you and demand money for "
        "'clearance'. No real officer ever arrests you over WhatsApp or video "
        "call. Never transfer money."
    ),
    "kyc_bank": (
        "A KYC/bank scam pretends your account or SIM will be blocked unless "
        "you 'verify' immediately. They want your OTP, PIN, or a link click "
        "to steal banking access. Never share an OTP or PIN with anyone, "
        "including someone claiming to be from your bank."
    ),
    "investment_stock": (
        "An investment scam offers guaranteed high returns through a 'VIP' "
        "trading group or advisor. They want you to deposit increasing "
        "amounts into their platform, which you can never withdraw from. "
        "Never send money for a 'guaranteed return' — no legitimate "
        "investment promises one."
    ),
    "courier_parcel": (
        "A courier/customs scam claims your parcel is held for illegal "
        "contents or unpaid duty. They want a 'clearance fee' or your "
        "personal/banking details to release it. Never pay a fee or share "
        "details for a parcel you did not order — verify directly with the "
        "courier's official app."
    ),
    "job_task": (
        "A task/job scam promises easy earnings for likes, ratings, or small "
        "tasks, then asks you to pay a 'prepaid task' fee to unlock higher "
        "payouts. They want your money, not your work. Never pay to earn — "
        "a real job never charges you upfront."
    ),
    "loan_app": (
        "A loan-app scam offers an instant loan with no documents, then "
        "demands an upfront 'processing fee' before disbursing anything. "
        "They want the fee, not to lend you money. Never pay an advance fee "
        "— use only RBI-registered lenders."
    ),
    "lottery_prize": (
        "A lottery/prize scam tells you that you've won a prize you never "
        "entered for, then asks for a 'processing fee' or your bank details "
        "to release it. They want your money or your account access. Never "
        "pay a fee or share bank details to claim a prize."
    ),
    "tech_support": (
        "A tech-support scam claims your device is infected and pushes you "
        "to install remote-access software like AnyDesk or TeamViewer. Once "
        "installed, they can see and control your device, including banking "
        "apps. Never install remote-access software for an unsolicited "
        "caller."
    ),
    "upi_collect_request": (
        "A UPI collect-request scam sends you a payment request disguised as "
        "a refund or prize, hoping you'll approve it with your UPI PIN. "
        "Approving a collect-request SENDS money, it never receives it. "
        "Never enter your UPI PIN to 'receive' money."
    ),
    "romance": (
        "A romance scam builds an online relationship over weeks or months, "
        "then invents an emergency — medical, customs, travel — that only "
        "your money can fix. They want repeated payments to someone you have "
        "never met in person. Never send money to an online partner you "
        "haven't verified in person."
    ),
    "deepfake_voice": (
        "A deepfake-voice scam uses an AI-cloned voice of a family member in "
        "urgent distress, asking for an immediate money transfer. They want "
        "you to act before you can verify. Never transfer money on a voice "
        "message alone — call the person back on their known number first."
    ),
    "other": (
        "This message showed suspicious signals — urgency, a request for "
        "money, or a request for personal/banking information — without "
        "matching one specific known scam pattern. Treat any unexpected "
        "request for money or credentials with suspicion. Never act on "
        "pressure alone; verify independently first."
    ),
}

_DEFAULT_EDUCATION_SCAM_TYPE = "other"


def followup_menu_text(lang: str) -> str:
    """The numbered follow-up menu appended after a SCAM verdict."""
    return _translate_template(lang, "followup_menu", _FOLLOWUP_MENU_EN)


def reporting_guidance_text(lang: str) -> str:
    """Reply for the '1' / 'report it' follow-up keyword.

    Stateless: we don't have the prior verdict, so this is a generic-but-
    useful template with [DATE]/[TYPE]/[AMOUNT] placeholders rather than a
    specific Chakshu category.
    """
    return _translate_template(lang, "reporting_guidance", _REPORTING_GUIDANCE_EN)


def emergency_guidance_text(lang: str) -> str:
    """Reply for the '2' / 'lost money' follow-up keyword."""
    return _translate_template(lang, "emergency_guidance", _EMERGENCY_GUIDANCE_EN)


def education_text(lang: str, scam_type: Optional[str] = None) -> str:
    """Reply for the '3' / 'tell me more' follow-up keyword.

    Stateless: without the prior verdict's scam_type, falls back to
    _DEFAULT_EDUCATION_SCAM_TYPE.
    """
    key = scam_type if scam_type in SCAM_EDUCATION else _DEFAULT_EDUCATION_SCAM_TYPE
    english = SCAM_EDUCATION[key]
    return _translate_template(lang, f"education_{key}", english)


def confirmation_text(lang: str) -> str:
    """Reply for the 'YES' / 'DONE' follow-up keyword."""
    return _translate_template(lang, "confirmation", _CONFIRMATION_EN)


def alternative_text(lang: str) -> str:
    """Reply for the 'NO' follow-up keyword."""
    return _translate_template(lang, "alternative", _ALTERNATIVE_EN)


def help_menu_text(lang: str) -> str:
    """Reply for the 'HELP' follow-up keyword."""
    return _translate_template(lang, "help_menu", _HELP_MENU_EN)


# Bare-word -> handler-key map. Matching is case-insensitive and only fires
# when the ENTIRE stripped message body is one of these tokens — a message
# with any other text (e.g. "1 please help me") is not intercepted and goes
# to the classification engine as normal, per CLAUDE.md task's stateless
# design constraint.
_FOLLOWUP_KEYWORDS: dict[str, str] = {
    "1": "report",
    "report it": "report",
    "2": "emergency",
    "lost money": "emergency",
    "3": "education",
    "tell me more": "education",
    "yes": "confirmation",
    "done": "confirmation",
    "no": "alternative",
    "help": "help",
}

_MAX_FOLLOWUP_KEYWORD_CHARS = 20


def match_followup_keyword(body: str) -> Optional[str]:
    """Return the follow-up handler key ('report' | 'emergency' | 'education'
    | 'confirmation' | 'alternative' | 'help') if `body` is ONLY a bare
    follow-up keyword, else None.

    A message containing any other text is not a follow-up — it's analyzed
    normally by the classification engine.
    """
    stripped = (body or "").strip()
    if not stripped or len(stripped) >= _MAX_FOLLOWUP_KEYWORD_CHARS:
        return None
    return _FOLLOWUP_KEYWORDS.get(stripped.lower())
