"""Screenshot text extraction via xAI Grok's vision-capable model.

Uses the same OpenAI-compatible SDK as services/llm.py, against a SEPARATE,
explicitly-configured vision model (settings.vision_model) — never silently
substitutes the text model or any other model if the vision model is
unavailable. Mirrors llm.py's defensive parsing / retry discipline, scoped
to the narrower extraction task.

Public API:
  - extract_text_from_image(image_bytes, mime_type) -> dict
        {"text": str, "sender": str | None}
    Raises VisionUnavailable on failure (missing key, network, invalid JSON
    after retries) — callers map this to HTTP 503.
    Raises VisionExtractionFailed when the model responded but produced no
    usable text — callers map this to HTTP 422.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any

import httpx
from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    OpenAI,
    RateLimitError,
)

from core.config import settings

log = logging.getLogger(__name__)


class VisionUnavailable(Exception):
    """The vision model could not be reached / produce a valid response
    after retries — maps to HTTP 503 (transient, try text paste instead)."""


class VisionExtractionFailed(Exception):
    """The vision model responded but no usable message text was found in
    the image — maps to HTTP 422 (the image itself is the problem)."""


SYSTEM_PROMPT = (
    "You are extracting text from a screenshot of an Indian SMS, WhatsApp "
    "message, or notification. Extract: (1) the full message text exactly "
    "as written, (2) the sender ID or phone number if visible (DLT "
    "registered sender IDs look like HDFCBK, VM-AXISBK, BP-CBSSBI, or "
    'similar 6-char alphanumeric codes; phone numbers are +91 or 10-digit). '
    'Respond ONLY with a JSON object: {"text": "...", "sender": "..."}. '
    "If sender is not visible, use null. Never add commentary."
)

_JSON_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_fences(text: str) -> str:
    return _JSON_FENCE.sub("", text).strip()


def _extract_content(resp) -> str:
    try:
        return resp.choices[0].message.content or ""
    except (AttributeError, IndexError) as e:
        raise ValueError(f"unexpected response shape: {e}")


def _validate(parsed: dict) -> dict:
    text = parsed.get("text")
    text = text.strip() if isinstance(text, str) else ""

    sender = parsed.get("sender")
    sender = sender.strip() if isinstance(sender, str) and sender.strip() else None

    return {"text": text, "sender": sender}


def _call_once(client: OpenAI, image_b64: str, mime_type: str, *, use_json_mode: bool) -> dict:
    data_url = f"data:{mime_type};base64,{image_b64}"
    kwargs: dict[str, Any] = dict(
        model=settings.vision_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Extract the message text and sender from this screenshot."},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            },
        ],
        temperature=0,
        max_tokens=1024,
    )
    if use_json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    resp = client.chat.completions.create(**kwargs)
    raw = _strip_fences(_extract_content(resp))
    if not raw:
        raise ValueError("empty vision response")

    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("vision model did not return a JSON object")

    return _validate(parsed)


def extract_text_from_image(image_bytes: bytes, mime_type: str) -> dict:
    """Extract {"text", "sender"} from a screenshot via Grok vision.

    Raises VisionUnavailable if the model/endpoint can't be reached or keeps
    failing after retries (caller -> 503, "try pasting text instead").
    Raises VisionExtractionFailed if the model responds successfully but
    finds no usable text in the image (caller -> 422).
    """
    if not settings.xai_api_key:
        raise VisionUnavailable("XAI_API_KEY is not configured")

    try:
        client = OpenAI(
            api_key=settings.xai_api_key,
            base_url=settings.base_url,
            timeout=settings.llm_timeout_s,
        )
    except Exception as e:
        raise VisionUnavailable(f"failed to init openai client: {e}") from e

    image_b64 = base64.b64encode(image_bytes).decode("ascii")

    use_json_mode = True
    last_err: Exception | None = None

    for attempt in range(settings.max_retries + 1):
        try:
            result = _call_once(client, image_b64, mime_type, use_json_mode=use_json_mode)
            if not result["text"]:
                raise VisionExtractionFailed("no text found in image")
            return result
        except VisionExtractionFailed:
            # Model responded successfully but found nothing — not a
            # transient failure, don't retry, don't mask as 503.
            raise
        except APIStatusError as e:
            status = getattr(e, "status_code", None)
            if use_json_mode and status == 400:
                log.warning(
                    "vision endpoint rejected response_format; disabling JSON mode and retrying"
                )
                use_json_mode = False
                continue
            last_err = e
            log.warning("vision attempt %d failed (HTTP %s): %s", attempt + 1, status, e)
            if status and status != 429 and status < 500:
                break
            if attempt < settings.max_retries:
                time.sleep(0.5 * (2**attempt))
        except (
            APITimeoutError,
            APIConnectionError,
            RateLimitError,
            APIError,
            httpx.HTTPError,
            json.JSONDecodeError,
            ValueError,
        ) as e:
            last_err = e
            log.warning("vision attempt %d failed: %s", attempt + 1, e)
            if attempt < settings.max_retries:
                time.sleep(0.5 * (2**attempt))
        except Exception as e:
            last_err = e
            log.warning("vision attempt %d failed (unexpected): %s", attempt + 1, e)
            if attempt < settings.max_retries:
                time.sleep(0.5 * (2**attempt))

    raise VisionUnavailable(f"vision model unavailable after retries: {last_err}")
