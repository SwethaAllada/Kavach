"""Lightweight lexical retriever, Supabase-backed with a JSON-file fallback.

No vector DB, no embeddings, stdlib only (+ httpx for the Supabase read,
mirroring services/store.py's existing pattern). Scores each KB entry by
overlap between the input text and the entry's `indicators` + `title`, using
a mix of substring / whole-token matching and TF-style weighting. Handles
English, Hindi, and Telugu because the KB stores indicator phrases in all
three scripts and we compare on lowercased NFC-normalized text.

Entry source, in priority order:
  1. A warm in-memory cache of rows from Supabase's `scam_patterns` table
     (status='approved'), TTL 300s.
  2. A fresh fetch from Supabase if the cache is cold/expired.
  3. The original data/scam_kb.json file (via `_load_kb()`, unchanged) if
     Supabase is unconfigured/unreachable/erroring, or if a fetch fails —
     the JSON path is the permanent fallback, never removed.

Public API (byte-identical contract to before this migration):
  - retrieve(text, top_k=3, min_similarity=0.15) -> list[dict]
  - get_kb() -> list[dict]  (returned entries mirror the JSON shape)
  - format_grounding_context(hits) -> str
  - invalidate_cache() -> None  (new — lets other modules force a reload)

Never raises: on any load/scoring failure it returns [] and logs a warning.
"""

from __future__ import annotations

import json
import logging
import re
import time
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import httpx

from core.config import settings

log = logging.getLogger(__name__)

# Resolve the KB path relative to the backend package (backend/services/rag.py
# -> backend/ -> project root -> data/scam_kb.json).
_KB_PATH = Path(__file__).resolve().parents[2] / "data" / "scam_kb.json"


def _normalize(text: str) -> str:
    """Lowercase, NFC-normalize, strip surrounding punctuation."""
    if not isinstance(text, str):
        text = str(text or "")
    text = unicodedata.normalize("NFC", text)
    return text.lower().strip()


# Devanagari (Hindi), Telugu, and Latin letters + digits count as word chars.
# Everything else is a separator. Using a permissive pattern so tokens survive
# across scripts.
_TOKEN_RE = re.compile(r"[\wऀ-ॿఀ-౿]+", flags=re.UNICODE)


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(_normalize(text))


@lru_cache(maxsize=1)
def _load_kb() -> list[dict]:
    """Load and cache the KB on first use. Returns [] on any failure."""
    try:
        with _KB_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            log.warning("scam_kb.json is not a list; ignoring")
            return []
        return data
    except FileNotFoundError:
        log.warning("scam_kb.json not found at %s", _KB_PATH)
        return []
    except Exception as e:
        log.exception("failed to load scam_kb.json: %s", e)
        return []


# ---------------------------------------------------------------------------
# Supabase-backed source (falls back to the JSON file above on any failure)
# ---------------------------------------------------------------------------

_TABLE = "scam_patterns"
_READ_TIMEOUT_S = 8.0
_CACHE_TTL_SECONDS = 300  # 5 minutes

# {"ts": epoch-seconds float | None, "entries": list[dict] | None}
_supabase_cache: dict = {"ts": None, "entries": None}


def _is_configured() -> bool:
    return bool(settings.supabase_url and settings.supabase_service_key)


def _rest_url() -> str:
    base = settings.supabase_url.rstrip("/")
    return f"{base}/rest/v1/{_TABLE}"


def _headers() -> dict:
    return {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
    }


def _coerce_list(value) -> list:
    """Defensively coerce a jsonb column's decoded value to a list — a
    hand-edited DB row could have malformed JSON in indicators/languages."""
    return value if isinstance(value, list) else []


def _reshape_row(row: dict) -> dict:
    """Reshape one Supabase scam_patterns row to the same dict shape as a
    data/scam_kb.json entry (id, category, title, indicators, why_scam,
    safe_action, source, languages)."""
    return {
        "id": row.get("id"),
        "category": row.get("category"),
        "title": row.get("title"),
        "indicators": _coerce_list(row.get("indicators")),
        "why_scam": row.get("why_scam", ""),
        "safe_action": row.get("safe_action", ""),
        "source": row.get("source", ""),
        "languages": _coerce_list(row.get("languages")) or ["en"],
    }


def _load_from_supabase() -> list[dict] | None:
    """Fetch all approved rows from Supabase's scam_patterns table.

    Returns None on ANY failure (unconfigured, network, timeout, non-2xx,
    bad JSON shape) — never raises, just logs a warning. On success, returns
    entries reshaped to the same shape as the JSON KB entries.
    """
    if not _is_configured():
        return None
    try:
        with httpx.Client(timeout=_READ_TIMEOUT_S) as client:
            resp = client.get(
                _rest_url(),
                headers=_headers(),
                params={"select": "*", "status": "eq.approved"},
            )
            if resp.status_code >= 300:
                log.warning(
                    "scam_patterns read failed: HTTP %s (%s)",
                    resp.status_code,
                    resp.reason_phrase,
                )
                return None
            data = resp.json()
            if not isinstance(data, list):
                log.warning("scam_patterns read: unexpected response shape (not a list)")
                return None
            return [_reshape_row(row) for row in data if isinstance(row, dict)]
    except Exception as e:
        log.warning("scam_patterns read error (falling back to JSON KB): %s", e)
        return None


def _cache_is_warm() -> bool:
    ts = _supabase_cache.get("ts")
    entries = _supabase_cache.get("entries")
    if ts is None or entries is None:
        return False
    return (time.time() - ts) < _CACHE_TTL_SECONDS


def invalidate_cache() -> None:
    """Force the next _get_entries() call to reload from Supabase.

    Public so other modules (e.g. routes/patterns.py, after auto-approving a
    new pattern) can make a freshly-inserted row visible to retrieve() on
    the very next call rather than waiting out the normal 5-minute TTL.
    """
    _supabase_cache["ts"] = None


def _get_entries() -> list[dict]:
    """Return the entry list to score against: Supabase-backed cache first,
    falling back to the JSON file (unchanged, existing behavior) if
    Supabase is unconfigured, unreachable, or errors — and NEVER discarding
    a still-good cache just because a refresh attempt failed."""
    if _cache_is_warm():
        return _supabase_cache["entries"]

    fresh = _load_from_supabase()
    if fresh is not None:
        _supabase_cache["entries"] = fresh
        _supabase_cache["ts"] = time.time()
        return fresh

    # Fetch failed. If we still have a (now technically-expired) cache from
    # an earlier success, prefer it over throwing away good data — same
    # philosophy as services/reputation.py's _refresh_cache_if_needed().
    if _supabase_cache.get("entries") is not None:
        return _supabase_cache["entries"]

    # No Supabase data has ever been available — fall back to the original
    # JSON-file KB, unchanged.
    return _load_kb()


def get_kb() -> list[dict]:
    """Public accessor for the entries currently in use (Supabase-backed
    cache when available, else the JSON file) — useful for tests /
    introspection."""
    return list(_get_entries())


def _score_entry(text_norm: str, text_tokens: set[str], entry: dict) -> tuple[float, list[str]]:
    """Return (raw_score, matched_indicator_phrases) for one KB entry.

    Scoring:
      +1.0 per indicator phrase that appears as a substring in the normalized text
      +0.6 per indicator token that appears as a token in the input (partial credit)
      +0.8 if any word of the title appears in the input tokens
    Multi-word phrases naturally get higher weight because they contribute
    both a substring hit AND partial-token hits.
    """
    raw = 0.0
    matched: list[str] = []

    indicators = entry.get("indicators") or []
    for phrase in indicators:
        if not isinstance(phrase, str) or not phrase:
            continue
        p_norm = _normalize(phrase)
        if not p_norm:
            continue
        # Full-phrase substring hit
        if p_norm in text_norm:
            raw += 1.0
            matched.append(phrase)
            continue
        # Partial-token hit (all tokens of the phrase appear as tokens in text)
        p_tokens = set(_TOKEN_RE.findall(p_norm))
        if p_tokens and p_tokens.issubset(text_tokens):
            raw += 0.6
            matched.append(phrase)

    title = entry.get("title") or ""
    title_tokens = set(_TOKEN_RE.findall(_normalize(title))) - {
        "a", "an", "the", "and", "or", "of", "on", "in", "to", "for", "with",
    }
    title_overlap = len(title_tokens & text_tokens)
    if title_overlap:
        raw += 0.8 * min(1.0, title_overlap / max(1, len(title_tokens)))

    return raw, matched


def _normalize_score(raw: float) -> float:
    """Map raw score -> similarity in [0, 1] with a soft saturation."""
    if raw <= 0:
        return 0.0
    # ~1 strong phrase hit ≈ 0.5, ~3+ hits saturate toward 1.
    return round(min(1.0, raw / (raw + 1.0) + 0.0), 3)


def retrieve(text: str, top_k: int = 3, min_similarity: float = 0.15) -> list[dict]:
    """Return the top-k KB entries most relevant to `text`.

    Each returned dict carries:
      id, category, title, similarity, why_scam, safe_action, source,
      matched_indicators (list of the phrases that hit).

    Returns [] on any failure or when nothing crosses `min_similarity`.
    """
    try:
        kb = _get_entries()
        if not kb or not text:
            return []
        text_norm = _normalize(text)
        text_tokens = set(_tokenize(text))
        if not text_tokens:
            return []

        scored: list[tuple[float, list[str], dict]] = []
        for entry in kb:
            raw, matched = _score_entry(text_norm, text_tokens, entry)
            sim = _normalize_score(raw)
            if sim >= min_similarity:
                scored.append((sim, matched, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        out: list[dict] = []
        for sim, matched, entry in scored[:top_k]:
            out.append(
                {
                    "id": entry.get("id"),
                    "category": entry.get("category"),
                    "title": entry.get("title"),
                    "similarity": sim,
                    "why_scam": entry.get("why_scam", ""),
                    "safe_action": entry.get("safe_action", ""),
                    "source": entry.get("source", ""),
                    "matched_indicators": matched,
                }
            )
        return out
    except Exception as e:
        log.exception("rag.retrieve failed silently: %s", e)
        return []


def format_grounding_context(hits: Iterable[dict]) -> str:
    """Render top-k hits as a compact block for injection into the LLM prompt.

    Kept short so it doesn't dominate the context window.
    """
    hits = list(hits)
    if not hits:
        return ""
    lines = [
        "Reference scam patterns that MAY be relevant "
        "(use as context — do not force a match; only cite if genuinely applicable):",
    ]
    for h in hits:
        title = h.get("title", "")
        why = h.get("why_scam", "")
        cat = h.get("category", "")
        lines.append(f"- [{h.get('id')}] ({cat}) {title} — {why}")
    return "\n".join(lines)
