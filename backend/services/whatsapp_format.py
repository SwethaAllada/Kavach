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

        body = "\n".join(parts)
        return _clip(body, MAX_MESSAGE_CHARS)
    except Exception:
        # Never let a formatting bug surface as a 500 to Twilio.
        return _whatsapp_string("en", "err")
