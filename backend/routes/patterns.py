"""Crowd-verified scam pattern intake.

POST /patterns/submit — users voluntarily submit a scam-message example.
  A deterministic (no LLM) 5-step pipeline decides whether to reject it
  (looks safe), report it as already-known, stage it as pending review, or
  auto-approve it into the live KB once 3+ independent reports of the same
  pattern have accumulated.

GET /patterns/stats — public counts of the KB's crowd-sourced growth.

On ANY Supabase failure anywhere in the submit pipeline, the safest
user-facing answer is a generic "thanks, we got it" — never a 500, never
infrastructure details leaked to the caller. Real errors are logged
server-side via pattern_store's own logging.
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from datetime import date, datetime, timezone

from fastapi import APIRouter, HTTPException

from models.schemas import PatternSubmitRequest
from services import pattern_store as pattern_store_service
from services import rag as rag_service
from services.classifier import _detect_language
from services.rules import SCAM_TAXONOMY, rules_classify

log = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Tokenization / stopwords — local to this module, mirrors the spirit of
# services/rag.py's tokenizer (lowercase, \w+ tokens) but adds an English
# stopword filter for the Jaccard-overlap steps below, which rag.py's own
# tokenizer does not need for its scoring approach.
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"\w+", re.UNICODE)

_STOPWORDS = {
    "a", "an", "the", "is", "are", "to", "of", "in", "on", "for", "and",
    "or", "with", "this", "that", "your", "you", "i", "my", "me",
}

# Same fix already established in services/classifier.py's _CASE_ID_ALPHABET /
# _generate_case_id(): secrets.token_urlsafe's base64 alphabet includes
# '-'/'_', which would violate "uppercase alphanumeric" — draw directly from
# [A-Z0-9] instead.
_PATTERN_ID_ALPHABET = string.ascii_uppercase + string.digits

_SIMILAR_PENDING_THRESHOLD = 0.70
_DUPLICATE_THRESHOLD = 0.85
_AUTO_APPROVE_MIN_SIMILAR_PENDING = 2


def _tokenize(text: str) -> set[str]:
    words = _WORD_RE.findall((text or "").lower())
    return {w for w in words if w not in _STOPWORDS}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


def _pattern_word_set(pattern: dict) -> set[str]:
    indicators = pattern.get("indicators") or []
    title = pattern.get("title") or ""
    joined = " ".join(indicators) + " " + title
    return _tokenize(joined)


def _generate_pattern_id() -> str:
    """USR-YYYYMMDD-XXXX, XXXX = 4 random uppercase alphanumeric chars."""
    today = date.today().strftime("%Y%m%d")
    suffix = "".join(secrets.choice(_PATTERN_ID_ALPHABET) for _ in range(4))
    return f"USR-{today}-{suffix}"


def _top_indicator_words(text: str, limit: int = 6) -> list[str]:
    """Top `limit` stopword-filtered words from `text`, deduped, sorted by
    length descending (longest words first), lowercased to match the KB's
    existing indicator style."""
    words = _WORD_RE.findall((text or "").lower())
    seen: list[str] = []
    seen_set: set[str] = set()
    for w in words:
        if w in _STOPWORDS or w in seen_set:
            continue
        seen_set.add(w)
        seen.append(w)
    seen.sort(key=len, reverse=True)
    return seen[:limit]


_STATS_FAILURE_SHAPE = {
    "approved_count": 0,
    "pending_count": 0,
    "auto_approved_count": 0,
    "last_updated": None,
    "status": "unavailable",
}


def get_stats_response() -> dict:
    """Shared by GET /patterns/stats and GET /trends' pattern_intelligence
    key. Returns the all-zeros/"unavailable" shape on any Supabase failure,
    never raises."""
    try:
        stats = pattern_store_service.get_pattern_stats()
    except Exception as e:  # defensive — get_pattern_stats itself shouldn't raise
        log.warning("get_stats_response: pattern_store raised (swallowed): %s", e)
        stats = None
    if stats is None:
        return dict(_STATS_FAILURE_SHAPE)
    return {
        "approved_count": stats["approved_count"],
        "pending_count": stats["pending_count"],
        "auto_approved_count": stats["auto_approved_count"],
        "last_updated": stats.get("last_updated"),
    }


@router.post("/patterns/submit")
def submit_pattern(request: PatternSubmitRequest) -> dict:
    try:
        return _run_submit_pipeline(request)
    except HTTPException:
        raise
    except Exception as e:
        # Deliberate simplification per spec: whatever failed, the safest
        # user-facing answer is a generic thanks — never leak infra errors.
        log.warning("patterns/submit pipeline failed (swallowed): %s", e)
        return {"status": "submitted", "message": "Thank you for your report."}


def _run_submit_pipeline(request: PatternSubmitRequest) -> dict:
    text = (request.text or "").strip()

    # STEP 1 — input validation.
    if not (20 <= len(text) <= 500):
        raise HTTPException(
            status_code=422,
            detail="text must be between 20 and 500 characters (after stripping whitespace).",
        )
    if request.source is not None and len(request.source) > 100:
        raise HTTPException(status_code=422, detail="source must be at most 100 characters.")

    # STEP 2 — auto-detect category (deterministic only, no LLM).
    rules_out = rules_classify(text)
    detected_category = rules_out["scam_type"]

    if detected_category == "likely_safe":
        return {
            "status": "rejected",
            "message": "This does not appear to be a scam pattern.",
        }

    if request.category and request.category in SCAM_TAXONOMY:
        category = request.category
    else:
        category = detected_category

    # STEP 3 — duplicate check against approved patterns.
    approved_patterns = pattern_store_service.fetch_approved_patterns() or []
    submitted_words = _tokenize(text)
    max_score = 0.0
    for pattern in approved_patterns:
        score = _jaccard(submitted_words, _pattern_word_set(pattern))
        if score > max_score:
            max_score = score
    if max_score > _DUPLICATE_THRESHOLD:
        return {
            "status": "known",
            "message": "This pattern is already in our knowledge base.",
        }

    # STEP 4 — count similar pending submissions in the same category.
    pending_rows = pattern_store_service.fetch_pending_by_category(category) or []
    similar_pending: list[dict] = []
    max_pending_similarity = 0.0
    for row in pending_rows:
        row_words = _tokenize(row.get("submitted_text") or "")
        score = _jaccard(submitted_words, row_words)
        if score > max_pending_similarity:
            max_pending_similarity = score
        if score > _SIMILAR_PENDING_THRESHOLD:
            similar_pending.append(row)

    detected_language = _detect_language(text)

    # STEP 5 — decide fate.
    if len(similar_pending) >= _AUTO_APPROVE_MIN_SIMILAR_PENDING:
        new_row = {
            "id": _generate_pattern_id(),
            "category": category,
            "title": f"User-reported: {category} pattern",
            "indicators": _top_indicator_words(text),
            "why_scam": "Crowd-verified by 3+ independent reports via Kavach.",
            "safe_action": "Do not respond or pay. Report to 1930.",
            "source": "Kavach user submissions (crowd-verified)",
            "languages": [detected_language or "en"],
            "status": "auto_approved",
            "submission_count": 3,
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }
        pattern_store_service.insert_scam_pattern(new_row)

        # Live on the very next retrieve() call, ahead of the normal 5-min TTL.
        rag_service.invalidate_cache()

        incorporated_ids = [
            str(row.get("id")) for row in similar_pending if row.get("id")
        ]
        pattern_store_service.mark_pending_incorporated(incorporated_ids)

        return {
            "status": "auto_approved",
            "message": (
                "This pattern has been verified by multiple users and is now "
                "active in Kavach's knowledge base. Thank you."
            ),
        }

    pending_row = {
        "submitted_text": text,
        "detected_category": category,
        "detected_language": detected_language or "en",
        # Max similarity against existing PENDING rows in this category
        # (step 4) — the step-3 duplicate score against approved patterns is
        # by definition <= 0.85 already, or we would not have reached here.
        "similarity_score": max_pending_similarity,
        "status": "pending",
        "submitted_via": "api",
    }
    pattern_store_service.insert_pending_pattern(pending_row)

    return {
        "status": "submitted",
        "message": "Thank you. This pattern will be reviewed and added if verified by other users.",
    }


@router.get("/patterns/stats")
def patterns_stats() -> dict:
    return get_stats_response()
