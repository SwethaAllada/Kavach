"""Supabase (PostgREST) client for the crowd-verified pattern pipeline.

Two tables, same house style as services/store.py:
  - `scam_patterns`   — the approved/auto_approved KB (mirrors data/scam_kb.json
    shape once approved; see deploy/supabase_scam_patterns.sql).
  - `pending_patterns` — user submissions awaiting review or auto-approval
    (see deploy/supabase_pending_patterns.sql).

routes/patterns.py's /patterns/submit pipeline needs to READ BACK results
synchronously (duplicate check against approved patterns, similar-pending
count) to decide its response, so — unlike services/store.py's fire-and-forget
telemetry writes — every function here is a plain synchronous httpx call with
a moderate timeout. Every failure mode is caught, logged, and reported back
to the caller as None / False / an "unavailable" signal; nothing here raises
into the request path except where a caller explicitly needs to distinguish
"zero rows" from "store unavailable" (see PatternStoreUnavailable, mirroring
services/store.py's AuditStoreUnavailable).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from core.config import settings

log = logging.getLogger(__name__)

_PATTERNS_TABLE = "scam_patterns"
_PENDING_TABLE = "pending_patterns"
_TIMEOUT_S = 8.0  # user-visible request path; a bit more generous than telemetry


# ---------------------------------------------------------------------------
# Availability + shared helpers
# ---------------------------------------------------------------------------

def _is_configured() -> bool:
    return bool(settings.supabase_url and settings.supabase_service_key)


def _rest_url(table: str) -> str:
    base = settings.supabase_url.rstrip("/")
    return f"{base}/rest/v1/{table}"


def _headers(*, prefer_return_minimal: bool = True) -> dict:
    h = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
    }
    if prefer_return_minimal:
        h["Prefer"] = "return=minimal"
    return h


class PatternStoreUnavailable(Exception):
    """Raised internally to signal Supabase is unconfigured/unreachable/
    erroring — distinct from a clean "0 rows" result. routes/patterns.py
    catches this (or the None/False sentinels the functions below return)
    and degrades to the safe fallback responses the spec defines; it never
    lets this escape into a 500."""


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def fetch_approved_patterns() -> Optional[list[dict]]:
    """Fetch all scam_patterns rows with status='approved' or
    'auto_approved' (both count as "already in the KB" for the duplicate
    check). Returns None on any failure."""
    if not _is_configured():
        return None
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            resp = client.get(
                _rest_url(_PATTERNS_TABLE),
                headers=_headers(prefer_return_minimal=False),
                params={
                    "select": "id,category,title,indicators,status",
                    "status": "in.(approved,auto_approved)",
                },
            )
            if resp.status_code >= 300:
                log.warning(
                    "scam_patterns fetch failed: HTTP %s (%s)",
                    resp.status_code, resp.reason_phrase,
                )
                return None
            data = resp.json()
            if not isinstance(data, list):
                log.warning("scam_patterns fetch: unexpected response shape")
                return None
            return data
    except Exception as e:
        log.warning("scam_patterns fetch error: %s", e)
        return None


def fetch_pending_by_category(category: str) -> Optional[list[dict]]:
    """Fetch pending_patterns rows with status='pending' and
    detected_category=`category`. Returns None on any failure."""
    if not _is_configured():
        return None
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            resp = client.get(
                _rest_url(_PENDING_TABLE),
                headers=_headers(prefer_return_minimal=False),
                params={
                    "select": "id,submitted_text,detected_category,status",
                    "detected_category": f"eq.{category}",
                    "status": "eq.pending",
                },
            )
            if resp.status_code >= 300:
                log.warning(
                    "pending_patterns fetch failed: HTTP %s (%s)",
                    resp.status_code, resp.reason_phrase,
                )
                return None
            data = resp.json()
            if not isinstance(data, list):
                log.warning("pending_patterns fetch: unexpected response shape")
                return None
            return data
    except Exception as e:
        log.warning("pending_patterns fetch error: %s", e)
        return None


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def insert_pending_pattern(row: dict) -> bool:
    """Insert one row into pending_patterns. Returns True on success, False
    on any failure (never raises)."""
    if not _is_configured():
        return False
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            resp = client.post(
                _rest_url(_PENDING_TABLE), headers=_headers(), json=row,
            )
            if resp.status_code >= 300:
                log.warning(
                    "pending_patterns insert failed: HTTP %s (%s)",
                    resp.status_code, resp.reason_phrase,
                )
                return False
            return True
    except Exception as e:
        log.warning("pending_patterns insert error: %s", e)
        return False


def insert_scam_pattern(row: dict) -> bool:
    """Insert one auto-approved row into scam_patterns. Returns True on
    success, False on any failure (never raises)."""
    if not _is_configured():
        return False
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            resp = client.post(
                _rest_url(_PATTERNS_TABLE), headers=_headers(), json=row,
            )
            if resp.status_code >= 300:
                log.warning(
                    "scam_patterns insert failed: HTTP %s (%s)",
                    resp.status_code, resp.reason_phrase,
                )
                return False
            return True
    except Exception as e:
        log.warning("scam_patterns insert error: %s", e)
        return False


def mark_pending_incorporated(ids: list[str]) -> bool:
    """Update the given pending_patterns rows (by id) to status='incorporated'.
    Returns True on success, False on any failure (never raises)."""
    if not _is_configured() or not ids:
        return False
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            resp = client.patch(
                _rest_url(_PENDING_TABLE),
                headers=_headers(),
                params={"id": f"in.({','.join(ids)})"},
                json={"status": "incorporated"},
            )
            if resp.status_code >= 300:
                log.warning(
                    "pending_patterns update failed: HTTP %s (%s)",
                    resp.status_code, resp.reason_phrase,
                )
                return False
            return True
    except Exception as e:
        log.warning("pending_patterns update error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Stats — shared by GET /patterns/stats and GET /trends' pattern_intelligence
# ---------------------------------------------------------------------------

def _count(table: str, params: dict) -> Optional[int]:
    """Return a row count via PostgREST's `Prefer: count=exact` + HEAD-style
    Content-Range response, or None on any failure."""
    if not _is_configured():
        return None
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            headers = _headers(prefer_return_minimal=False)
            headers["Prefer"] = "count=exact"
            params = {**params, "select": "id", "limit": "1"}
            resp = client.get(_rest_url(table), headers=headers, params=params)
            if resp.status_code >= 300:
                log.warning(
                    "%s count failed: HTTP %s (%s)",
                    table, resp.status_code, resp.reason_phrase,
                )
                return None
            content_range = resp.headers.get("content-range", "")
            # Format is "0-0/N" (or "*/N"); N is the total count.
            if "/" in content_range:
                total = content_range.rsplit("/", 1)[-1]
                if total.isdigit():
                    return int(total)
            log.warning("%s count: no usable Content-Range (%r)", table, content_range)
            return None
    except Exception as e:
        log.warning("%s count error: %s", table, e)
        return None


def get_pattern_stats() -> Optional[dict]:
    """Compute {approved_count, pending_count, auto_approved_count,
    last_updated} across scam_patterns + pending_patterns.

    - approved_count: scam_patterns where status='approved'.
    - auto_approved_count: scam_patterns where status='auto_approved'.
    - pending_count: pending_patterns where status='pending'.
    - last_updated: most recent scam_patterns.created_at (the KB's own
      freshness signal) — chosen over "now" so the field actually reflects
      when the KB last changed, and over pending_patterns.created_at
      because a stream of raw submissions changing the timestamp even when
      nothing was approved would be misleading for a "KB freshness" field.

    Returns None if ANY of the three counts can't be determined (Supabase
    unconfigured/unreachable/erroring) — callers should treat None as
    "unavailable" and degrade to the all-zeros response.
    """
    if not _is_configured():
        return None

    approved = _count(_PATTERNS_TABLE, {"status": "eq.approved"})
    auto_approved = _count(_PATTERNS_TABLE, {"status": "eq.auto_approved"})
    pending = _count(_PENDING_TABLE, {"status": "eq.pending"})

    if approved is None or auto_approved is None or pending is None:
        return None

    last_updated = _latest_created_at(_PATTERNS_TABLE)

    return {
        "approved_count": approved,
        "pending_count": pending,
        "auto_approved_count": auto_approved,
        "last_updated": last_updated,
    }


def _latest_created_at(table: str) -> Optional[str]:
    """Best-effort: most recent created_at in `table`, ISO string, or None
    if unavailable — this is a "nice to have" field, so a failure here does
    NOT make get_pattern_stats() return None overall."""
    try:
        with httpx.Client(timeout=_TIMEOUT_S) as client:
            resp = client.get(
                _rest_url(table),
                headers=_headers(prefer_return_minimal=False),
                params={"select": "created_at", "order": "created_at.desc", "limit": "1"},
            )
            if resp.status_code >= 300:
                return None
            data = resp.json()
            if isinstance(data, list) and data:
                return data[0].get("created_at")
            return None
    except Exception as e:
        log.warning("%s last_updated fetch error: %s", table, e)
        return None
