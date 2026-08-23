"""Twilio-compatible WhatsApp / SMS webhook.

Design point of this file: WhatsApp is a THIN adapter over the shared engine.
The endpoint parses Twilio's form-encoded inbound-message payload, calls the
same `classifier.analyze()` the web `/analyze` route calls, and returns a
TwiML reply. No new AI, no new logic, no branches on channel.

Signature verification is toggleable via `settings.verify_twilio_signature` so
this file can be unit-tested and demo'd locally without live Twilio
credentials. In production the flag flips to true.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
from urllib.parse import quote
from xml.sax.saxutils import escape as xml_escape

from fastapi import APIRouter, Request, Response

from core.config import settings
from services.classifier import analyze
from services.whatsapp_format import (
    confirmation_text,
    education_text,
    emergency_guidance_text,
    help_menu_text,
    alternative_text,
    match_followup_keyword,
    reporting_guidance_text,
    verdict_to_whatsapp_text,
)

# Stateless follow-up handlers (see whatsapp_format.match_followup_keyword).
# No verdict/session context is available for these, so each renders a
# templated reply in English — the WhatsApp follow-up flow is not yet
# language-aware for these specific replies (only the scam verdict text and
# menu it follows are).
_FOLLOWUP_HANDLERS = {
    "report": lambda: reporting_guidance_text("en"),
    "emergency": lambda: emergency_guidance_text("en"),
    "education": lambda: education_text("en"),
    "confirmation": lambda: confirmation_text("en"),
    "alternative": lambda: alternative_text("en"),
    "help": lambda: help_menu_text("en"),
}

log = logging.getLogger(__name__)

router = APIRouter()

# Bare minimum reply Twilio can render if something goes very wrong.
_FALLBACK_TEXT = (
    "Sorry, we couldn't analyze that message just now. Please try again in a moment."
)


def _twiml(text: str) -> Response:
    """Wrap plain text in a valid TwiML <Response><Message>...</Message></Response>.

    XML-escapes the body so a user message with characters like `<` or `&`
    can't break the response.
    """
    body = xml_escape(text or "")
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<Response><Message>{body}</Message></Response>"
    )
    return Response(content=xml, media_type="application/xml")


def _twilio_expected_signature(auth_token: str, url: str, form: dict) -> str:
    """Compute Twilio's expected X-Twilio-Signature for a form-encoded request.

    Algorithm (per Twilio's docs):
      1. Start with the full request URL (scheme, host, path, and any query).
      2. Sort the POST parameters alphabetically by key.
      3. Concatenate: for each (k, v) in sorted order, append k then v (no
         separator).
      4. HMAC-SHA1 the result with the auth token.
      5. Base64 the digest.
    """
    payload = url
    for k in sorted(form.keys()):
        payload += k + str(form[k])
    digest = hmac.new(
        auth_token.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def _reconstruct_url(request: Request) -> str:
    """The URL as Twilio saw it. Behind a proxy Twilio signs the ORIGINAL
    URL, so honor `X-Forwarded-Proto` / `X-Forwarded-Host` when present.
    """
    # Twilio signs the URL the client hit, which for us is the public webhook
    # URL. Behind a proxy we honor the standard forwarded headers.
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    path = request.url.path
    query = request.url.query
    url = f"{proto}://{host}{path}"
    if query:
        url += f"?{query}"
    return url


async def _verify_signature(request: Request, form: dict) -> bool:
    """Return True when the request's X-Twilio-Signature matches. False when
    verification is enabled but the header/token/computation disagrees.

    Callers should only invoke this when `settings.verify_twilio_signature` is
    True — when the flag is off, we don't verify at all.
    """
    provided = request.headers.get("x-twilio-signature") or ""
    if not provided:
        return False
    if not settings.twilio_auth_token:
        # Verification is enabled but no token is configured — fail closed.
        return False
    url = _reconstruct_url(request)
    expected = _twilio_expected_signature(settings.twilio_auth_token, url, form)
    return hmac.compare_digest(provided, expected)


@router.post("/webhook")
async def webhook(request: Request) -> Response:
    """Twilio inbound webhook: reply with a TwiML message.

    Twilio sends `application/x-www-form-urlencoded` with fields including
    `Body`, `From`, `To`, `WaId`, `MessageSid`. We only need `Body`. Every
    error path still returns a valid TwiML — Twilio treats non-2xx or
    non-TwiML responses as delivery failures and will retry, which we do
    not want.
    """
    try:
        form = dict((await request.form()) or {})
    except Exception as e:
        log.warning("webhook: failed to parse form body: %s", e)
        return _twiml(_FALLBACK_TEXT)

    # Signature check (opt-in). We verify BEFORE calling the engine, so an
    # unauthenticated caller can't drive LLM traffic through us.
    if settings.verify_twilio_signature:
        try:
            ok = await _verify_signature(request, form)
        except Exception as e:
            log.warning("webhook: signature check errored: %s", e)
            ok = False
        if not ok:
            log.warning("webhook: rejected request with invalid Twilio signature")
            return Response(status_code=403, content="Invalid Twilio signature")

    body = str(form.get("Body") or "").strip()
    if not body:
        return _twiml(_FALLBACK_TEXT)

    # Conversational follow-up flow: a bare keyword ("1", "YES", "HELP", ...)
    # is intercepted BEFORE the classification engine runs, and answered from
    # a pre-built template — no LLM call. Any other content (including a
    # keyword plus extra words) falls through to analyze() as a new message.
    followup_key = match_followup_keyword(body)
    if followup_key is not None:
        try:
            reply = _FOLLOWUP_HANDLERS[followup_key]()
        except Exception as e:
            log.exception("webhook: follow-up handler %r failed: %s", followup_key, e)
            reply = _FALLBACK_TEXT
        return _twiml(reply)

    # SAME engine the web /analyze route uses. This line is the point of the
    # whole phase — no new AI, no new logic, one path.
    try:
        verdict = analyze(body)
    except Exception as e:
        log.exception("webhook: analyze() failed: %s", e)
        return _twiml(_FALLBACK_TEXT)

    try:
        reply = verdict_to_whatsapp_text(verdict)
    except Exception as e:
        log.exception("webhook: formatter failed: %s", e)
        reply = _FALLBACK_TEXT

    return _twiml(reply)
