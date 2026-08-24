"""Twilio-compatible WhatsApp / SMS webhook.

Design point of this file: WhatsApp is a THIN adapter over the shared engine.
The endpoint parses Twilio's form-encoded inbound-message payload, calls the
same `classifier.analyze()` the web `/analyze` route calls, and returns a
TwiML reply. No new AI, no new logic, no branches on channel.

Signature verification is toggleable via `settings.verify_twilio_signature` so
this file can be unit-tested and demo'd locally without live Twilio
credentials. In production the flag flips to true.

Conversational intelligence: General questions (e.g. "What can you do?",
"How does this work?") are detected via is_general_question() and answered
by the LLM conversationally, without running scam analysis. This keeps the
bot friendly and helpful for non-scam queries.

Image support: WhatsApp images (screenshots) are downloaded from Twilio's
MediaUrl, processed via the vision service to extract text, and then
analyzed like any other message.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
from urllib.parse import quote
from xml.sax.saxutils import escape as xml_escape

import httpx
from fastapi import APIRouter, Request, Response

from core.config import settings
from services.classifier import analyze
from services.llm import answer_general_query
from services.vision import (
    extract_text_from_image,
    VisionUnavailable,
    VisionExtractionFailed,
)
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

# ---------------------------------------------------------------------------
# Conversational message detection (conversational intelligence)
#
# A "conversational message" is a short, non-scam message that should be
# answered conversationally by the LLM instead of being analyzed as a
# potential scam. This includes:
# - Greetings (hello, hi, good morning, etc.)
# - Questions about Kavach or fraud safety
# - Simple responses (thanks, ok, etc.)
# ---------------------------------------------------------------------------

# Maximum length for a conversational message (longer messages are likely
# scam reports or forwarded messages, not simple conversation).
_MAX_CONVERSATIONAL_CHARS = 120

# Greetings and simple conversational phrases in multiple languages.
# These are matched exactly (case-insensitive) or as prefixes.
_GREETINGS_EN = (
    "hi", "hello", "hey", "hii", "hiii", "helo", "hellow",
    "good morning", "good afternoon", "good evening", "good night",
    "gm", "gn", "morning", "evening",
    "thanks", "thank you", "thankyou", "thx", "ty",
    "ok", "okay", "okk", "okkk", "k", "kk",
    "bye", "goodbye", "good bye", "see you", "take care",
    "welcome", "you're welcome", "np", "no problem",
    "sorry", "apologies",
    "nice", "great", "awesome", "cool", "good", "fine", "perfect",
    "got it", "understood", "i see", "alright", "sure",
)

# Hindi greetings
_GREETINGS_HI = (
    "नमस्ते", "नमस्कार", "प्रणाम", "राम राम", "जय श्री राम",
    "सुप्रभात", "शुभ रात्रि", "शुभ संध्या",
    "धन्यवाद", "शुक्रिया", "थैंक्स",
    "ठीक है", "अच्छा", "हां", "हाँ", "जी", "जी हां",
    "अलविदा", "फिर मिलेंगे",
    "namaste", "namaskar", "pranam", "dhanyavad", "shukriya",
    "theek hai", "accha", "haan", "ji",
)

# Telugu greetings
_GREETINGS_TE = (
    "నమస్కారం", "నమస్తే", "శుభోదయం", "శుభ రాత్రి",
    "ధన్యవాదాలు", "థాంక్స్",
    "సరే", "అవును", "ఓకే",
    "namaskaram", "namaste", "dhanyavaadalu",
)

# Tamil greetings
_GREETINGS_TA = (
    "வணக்கம்", "நன்றி", "சரி", "ஓகே",
    "vanakkam", "nandri",
)

# Kannada greetings
_GREETINGS_KN = (
    "ನಮಸ್ಕಾರ", "ಧನ್ಯವಾದ", "ಸರಿ", "ಓಕೆ",
    "namaskara", "dhanyavada",
)

# Malayalam greetings
_GREETINGS_ML = (
    "നമസ്കാരം", "നന്ദി", "ശരി", "ഓക്കേ",
    "namaskaram", "nandi",
)

# Bengali greetings
_GREETINGS_BN = (
    "নমস্কার", "ধন্যবাদ", "ঠিক আছে", "ওকে",
    "nomoskar", "dhonnobad",
)

# Marathi greetings
_GREETINGS_MR = (
    "नमस्कार", "धन्यवाद", "ठीक आहे", "ओके",
)

# Gujarati greetings
_GREETINGS_GU = (
    "નમસ્તે", "આભાર", "ઠીક છે", "ઓકે",
)

# Punjabi greetings
_GREETINGS_PA = (
    "ਸਤ ਸ੍ਰੀ ਅਕਾਲ", "ਧੰਨਵਾਦ", "ਠੀਕ ਹੈ", "ਓਕੇ",
    "sat sri akal",
)

# Urdu greetings
_GREETINGS_UR = (
    "السلام علیکم", "شکریہ", "ٹھیک ہے",
    "assalam alaikum", "shukriya",
)

# All greetings combined
_GREETINGS = (
    _GREETINGS_EN + _GREETINGS_HI + _GREETINGS_TE + _GREETINGS_TA +
    _GREETINGS_KN + _GREETINGS_ML + _GREETINGS_BN + _GREETINGS_MR +
    _GREETINGS_GU + _GREETINGS_PA + _GREETINGS_UR
)

# Question starters in English and common Indian languages.
# These are checked case-insensitively at the start of the message.
_QUESTION_STARTERS_EN = (
    "what", "how", "why", "when", "where", "who", "can", "does", "is", "are",
    "tell", "help", "explain", "do", "will", "should", "could", "would",
)

# Hindi question starters (Devanagari and transliterated)
_QUESTION_STARTERS_HI = (
    "क्या", "कैसे", "क्यों", "कब", "कहां", "कहाँ", "कौन", "किसने", "किसको",
    "बताओ", "बताइए", "समझाओ", "मदद", "कृपया",
    "kya", "kaise", "kyun", "kyon", "kab", "kahan", "kaun", "kisne", "kisko",
    "batao", "bataiye", "samjhao", "madad",
)

# Telugu question starters
_QUESTION_STARTERS_TE = (
    "ఏమి", "ఎలా", "ఎందుకు", "ఎప్పుడు", "ఎక్కడ", "ఎవరు", "చెప్పు", "చెప్పండి",
    "సహాయం", "emi", "ela", "enduku", "eppudu", "ekkada", "evaru", "cheppu",
)

# Tamil question starters
_QUESTION_STARTERS_TA = (
    "என்ன", "எப்படி", "ஏன்", "எப்போது", "எங்கே", "யார்", "சொல்லு", "உதவி",
    "enna", "eppadi", "en", "yen", "eppo", "enge", "yaar", "sollu", "udavi",
)

# Kannada question starters
_QUESTION_STARTERS_KN = (
    "ಏನು", "ಹೇಗೆ", "ಯಾಕೆ", "ಯಾವಾಗ", "ಎಲ್ಲಿ", "ಯಾರು", "ಹೇಳಿ", "ಸಹಾಯ",
    "enu", "hege", "yaake", "yaavaga", "elli", "yaaru", "heli", "sahaaya",
)

# Malayalam question starters
_QUESTION_STARTERS_ML = (
    "എന്താണ്", "എങ്ങനെ", "എന്തുകൊണ്ട്", "എപ്പോൾ", "എവിടെ", "ആര്", "പറയൂ", "സഹായം",
    "enthaanu", "engane", "enthukond", "eppol", "evide", "aaru", "parayoo", "sahaayam",
)

# Bengali question starters
_QUESTION_STARTERS_BN = (
    "কি", "কী", "কেন", "কখন", "কোথায়", "কে", "বলো", "সাহায্য",
    "ki", "keno", "kokhon", "kothay", "ke", "bolo", "sahayya",
)

# Marathi question starters
_QUESTION_STARTERS_MR = (
    "काय", "कसे", "का", "केव्हा", "कुठे", "कोण", "सांगा", "मदत",
    "kay", "kase", "ka", "kevha", "kuthe", "kon", "sanga", "madat",
)

# Gujarati question starters
_QUESTION_STARTERS_GU = (
    "શું", "કેવી", "કેમ", "ક્યારે", "ક્યાં", "કોણ", "કહો", "મદદ",
    "shu", "kevi", "kem", "kyare", "kyan", "kon", "kaho", "madad",
)

# Punjabi question starters
_QUESTION_STARTERS_PA = (
    "ਕੀ", "ਕਿਵੇਂ", "ਕਿਉਂ", "ਕਦੋਂ", "ਕਿੱਥੇ", "ਕੌਣ", "ਦੱਸੋ", "ਮਦਦ",
    "ki", "kiven", "kion", "kadon", "kithe", "kaun", "dasso", "madad",
)

# Odia question starters
_QUESTION_STARTERS_OR = (
    "କଣ", "କିପରି", "କାହିଁକି", "କେବେ", "କେଉଁଠି", "କିଏ", "କୁହ", "ସାହାଯ୍ୟ",
    "kana", "kipari", "kahinki", "kebe", "keunthi", "kie", "kuha", "sahayya",
)

# Urdu question starters
_QUESTION_STARTERS_UR = (
    "کیا", "کیسے", "کیوں", "کب", "کہاں", "کون", "بتاؤ", "مدد",
)

# Assamese question starters
_QUESTION_STARTERS_AS = (
    "কি", "কেনেকৈ", "কিয়", "কেতিয়া", "ক'ত", "কোন", "কওক", "সহায়",
)

# All question starters combined
_QUESTION_STARTERS = (
    _QUESTION_STARTERS_EN + _QUESTION_STARTERS_HI + _QUESTION_STARTERS_TE +
    _QUESTION_STARTERS_TA + _QUESTION_STARTERS_KN + _QUESTION_STARTERS_ML +
    _QUESTION_STARTERS_BN + _QUESTION_STARTERS_MR + _QUESTION_STARTERS_GU +
    _QUESTION_STARTERS_PA + _QUESTION_STARTERS_OR + _QUESTION_STARTERS_UR +
    _QUESTION_STARTERS_AS
)

# Scam signal keywords — if ANY of these appear, it's NOT a conversational message.
# These are checked case-insensitively anywhere in the message.
_SCAM_SIGNAL_KEYWORDS = (
    # English scam signals
    "otp", "bank", "transfer", "arrest", "parcel", "aadhaar", "aadhar",
    "cbi", "kyc", "upi", "lottery", "prize", "customs", "blocked",
    "verify", "verification", "account", "suspend", "urgent", "immediately",
    "click", "link", "install", "download", "refund", "claim", "won",
    "winner", "lakhs", "lakh", "crore", "rupees", "rs.", "inr", "payment",
    "police", "court", "legal", "case", "fir", "warrant", "summon",
    "hdfc", "icici", "sbi", "axis", "kotak", "paytm", "phonepe", "gpay",
    "whatsapp", "telegram", "video call", "skype", "anydesk", "teamviewer",
    "pan card", "pan number", "credit card", "debit card", "cvv", "pin",
    "password", "passcode", "atm", "neft", "rtgs", "imps",
    # Hindi scam signals
    "गिरफ्तार", "पार्सल", "आधार", "बैंक", "ट्रांसफर", "पुलिस", "कोर्ट",
    "केस", "वारंट", "सम्मन", "ब्लॉक", "वेरिफाई", "अकाउंट", "पेमेंट",
    "लॉटरी", "इनाम", "जीता", "लाख", "करोड़", "रुपये",
    # Telugu scam signals
    "అరెస్ట్", "పార్సెల్", "ఆధార్", "బ్యాంక్", "ట్రాన్స్ఫర్", "పోలీస్",
    "కోర్ట్", "కేస్", "వారంట్", "సమన్స్", "బ్లాక్", "వెరిఫై", "అకౌంట్",
)

# Compile a regex pattern for scam signals (case-insensitive)
_SCAM_SIGNAL_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(kw) for kw in _SCAM_SIGNAL_KEYWORDS) + r")",
    re.IGNORECASE,
)


def _is_greeting(text: str) -> bool:
    """Check if text is a greeting or simple conversational phrase."""
    text_lower = text.lower().strip()
    # Exact match
    if text_lower in (g.lower() for g in _GREETINGS):
        return True
    # Check if starts with a greeting (e.g., "hello there", "hi how are you")
    for greeting in _GREETINGS:
        gl = greeting.lower()
        if text_lower == gl or text_lower.startswith(gl + " ") or text_lower.startswith(gl + ","):
            return True
    return False


def _is_question(text: str) -> bool:
    """Check if text is a question (ends with ? or starts with question word)."""
    text_lower = text.lower()

    # Check if ends with question mark
    if text.rstrip().endswith("?"):
        return True

    # Check if starts with a question word (any language)
    for starter in _QUESTION_STARTERS:
        sl = starter.lower()
        if text_lower.startswith(sl) or text_lower.startswith(sl + " "):
            return True

    return False


def is_general_question(text: str) -> bool:
    """Detect if `text` is a conversational message (greeting, question, etc.).

    A message is conversational (not a scam to analyze) when ALL of:
    - It is SHORT (under 120 chars)
    - It does NOT contain any scam signal keywords
    - It is EITHER:
      - A greeting/simple phrase (hello, thanks, ok, etc.)
      - A question (ends with ? OR starts with a question word)

    Returns True if the message should be answered conversationally,
    False if it should be analyzed as a potential scam.
    """
    if not text:
        return False

    text = text.strip()

    # Must be short (under 120 chars)
    if len(text) > _MAX_CONVERSATIONAL_CHARS:
        return False

    # Check for scam signal keywords — if any present, NOT conversational
    if _SCAM_SIGNAL_PATTERN.search(text):
        return False

    # Check if it's a greeting OR a question
    if _is_greeting(text) or _is_question(text):
        return True

    return False


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


# ---------------------------------------------------------------------------
# Image handling for WhatsApp screenshots
# ---------------------------------------------------------------------------

# Allowed image MIME types for WhatsApp media
_ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}

# Maximum image size to download (5MB)
_MAX_IMAGE_BYTES = 5 * 1024 * 1024

# Error messages for image processing
_IMAGE_FALLBACK_TEXT = (
    "I couldn't process that image. Please try:\n"
    "• Taking a clearer screenshot\n"
    "• Copying and pasting the message text directly\n\n"
    "Forward me any suspicious message to check it."
)

_IMAGE_TOO_LARGE_TEXT = (
    "That image is too large. Please send a smaller screenshot (under 5MB) "
    "or paste the message text directly."
)

_IMAGE_UNSUPPORTED_TEXT = (
    "I can only analyze image screenshots (JPEG, PNG). "
    "Please send a screenshot of the suspicious message, or paste the text directly."
)


async def _download_twilio_media(media_url: str) -> tuple[bytes | None, str | None]:
    """Download media from Twilio's URL with Basic Auth.

    Twilio media URLs require authentication using Account SID and Auth Token.
    Returns (image_bytes, error_message) tuple.
    """
    if not media_url:
        return None, "No media URL provided"

    # Check if credentials are configured
    if not settings.twilio_account_sid or not settings.twilio_auth_token:
        log.error("webhook: Twilio credentials not configured for media download")
        return None, "Media download not configured"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Twilio requires Basic Auth for media downloads
            auth = (settings.twilio_account_sid, settings.twilio_auth_token)

            log.info("webhook: downloading media from Twilio: %s", media_url[:100])
            response = await client.get(media_url, auth=auth, follow_redirects=True)

            if response.status_code == 401:
                log.error("webhook: Twilio auth failed (401) - check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN")
                return None, "Authentication failed"

            if response.status_code == 404:
                log.error("webhook: Media not found (404) - URL may have expired")
                return None, "Media not found"

            response.raise_for_status()

            # Check size
            if len(response.content) > _MAX_IMAGE_BYTES:
                log.warning("webhook: media too large: %d bytes", len(response.content))
                return None, "Image too large"

            log.info("webhook: downloaded %d bytes from Twilio", len(response.content))
            return response.content, None

    except httpx.TimeoutException as e:
        log.warning("webhook: timeout downloading media: %s", e)
        return None, "Download timed out"
    except httpx.HTTPStatusError as e:
        log.warning("webhook: HTTP error downloading media: %s", e)
        return None, f"HTTP error: {e.response.status_code}"
    except Exception as e:
        log.exception("webhook: failed to download media from %s: %s", media_url, e)
        return None, str(e)


def _extract_text_from_whatsapp_image(image_bytes: bytes, content_type: str) -> str | None:
    """Extract text from a WhatsApp image using the vision service.

    Returns the extracted text, or None on failure.
    """
    try:
        result = extract_text_from_image(image_bytes, content_type)
        text = result.get("text", "").strip()
        if text:
            return text
        return None
    except VisionExtractionFailed as e:
        log.warning("webhook: vision extraction failed: %s", e)
        return None
    except VisionUnavailable as e:
        log.warning("webhook: vision service unavailable: %s", e)
        return None
    except Exception as e:
        log.exception("webhook: unexpected vision error: %s", e)
        return None


@router.post("/webhook")
async def webhook(request: Request) -> Response:
    """Twilio inbound webhook: reply with a TwiML message.

    Twilio sends `application/x-www-form-urlencoded` with fields including
    `Body`, `From`, `To`, `WaId`, `MessageSid`. For media messages, Twilio
    also sends `NumMedia`, `MediaUrl0`, `MediaContentType0`, etc.

    Every error path still returns a valid TwiML — Twilio treats non-2xx or
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

    # Check for media attachments (images)
    num_media = int(form.get("NumMedia") or 0)
    media_url = str(form.get("MediaUrl0") or "").strip()
    media_type = str(form.get("MediaContentType0") or "").strip()

    body = str(form.get("Body") or "").strip()

    # Handle image messages (screenshots)
    if num_media > 0 and media_url:
        log.info("webhook: received media message, type=%s, url=%s", media_type, media_url[:80])

        # Check if it's a supported image type
        if media_type not in _ALLOWED_IMAGE_TYPES:
            log.warning("webhook: unsupported media type: %s", media_type)
            return _twiml(_IMAGE_UNSUPPORTED_TEXT)

        # Download the image from Twilio
        image_bytes, download_error = await _download_twilio_media(media_url)
        if image_bytes is None:
            log.error("webhook: image download failed: %s", download_error)
            if download_error == "Image too large":
                return _twiml(_IMAGE_TOO_LARGE_TEXT)
            return _twiml(_IMAGE_FALLBACK_TEXT)

        log.info("webhook: downloaded image, %d bytes", len(image_bytes))

        # Extract text from the image using vision
        extracted_text = _extract_text_from_whatsapp_image(image_bytes, media_type)
        if not extracted_text:
            log.error("webhook: vision extraction returned no text")
            return _twiml(_IMAGE_FALLBACK_TEXT)

        # Use the extracted text for analysis (combine with any caption)
        if body:
            # User sent image with a caption — use caption as context
            body = f"{body}\n\n[Extracted from image:]\n{extracted_text}"
        else:
            body = extracted_text

        log.info("webhook: extracted %d chars from image", len(extracted_text))

    # No body and no media — nothing to analyze
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

    # Conversational intelligence: general questions about Kavach or fraud
    # safety are answered conversationally by the LLM, without scam analysis.
    # This makes the bot feel more helpful and natural for non-scam queries.
    if is_general_question(body):
        try:
            reply = answer_general_query(body)
            # Conversational replies get a simple signature, no follow-up menu
            reply = f"{reply}\n\n— Kavach"
        except Exception as e:
            log.exception("webhook: answer_general_query() failed: %s", e)
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
