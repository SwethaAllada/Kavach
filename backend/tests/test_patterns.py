"""Tests for routes/patterns.py — POST /patterns/submit, GET /patterns/stats,
and the pattern_intelligence key added to GET /trends.

All Supabase calls (via services.pattern_store) are mocked at the
module-attribute level (monkeypatch.setattr(pattern_store_module, "fn", fake))
so tests never touch the network. The LLM is not involved at all in this
pipeline (rules_classify only), so no LLM mocking is needed here.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from main import app
from routes import patterns as patterns_route
from services import pattern_store as pattern_store_module
from services import rag as rag_module

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clear_patterns_rate_limiter():
    """The /patterns/submit limiter is a small (3/hour) global singleton in
    main.py — clear it before/after every test so tests don't interfere."""
    import main as main_module
    main_module._patterns_limiter.clear()
    yield
    main_module._patterns_limiter.clear()


# A message long enough (20-500 chars) and clearly scam-shaped so
# rules_classify does not call it likely_safe.
_SCAM_TEXT = "This is CBI, digital arrest warrant issued, stay on this call now"
_SAFE_TEXT = "Hi mom, reached office safely. Will call after lunch today, love you"


def _no_approved(*args, **kwargs):
    return []


def _no_pending(*args, **kwargs):
    return []


# ---------------------------------------------------------------------------
# 3. text < 20 chars -> 422
# ---------------------------------------------------------------------------

def test_submit_rejects_too_short_text():
    r = client.post("/patterns/submit", json={"text": "too short"})
    assert r.status_code == 422


def test_submit_rejects_too_long_source(monkeypatch):
    monkeypatch.setattr(pattern_store_module, "fetch_approved_patterns", _no_approved)
    monkeypatch.setattr(pattern_store_module, "fetch_pending_by_category", _no_pending)
    r = client.post(
        "/patterns/submit",
        json={"text": _SCAM_TEXT, "source": "x" * 101},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# 4. likely_safe text -> rejected
# ---------------------------------------------------------------------------

def test_submit_rejects_likely_safe_message(monkeypatch):
    r = client.post("/patterns/submit", json={"text": _SAFE_TEXT})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "rejected"


def test_submit_rejects_based_on_auto_detected_category_even_if_caller_lies(monkeypatch):
    """A caller cannot bypass the safety check by supplying a fake category —
    rejection is always based on rules_classify(text) itself."""
    r = client.post(
        "/patterns/submit",
        json={"text": _SAFE_TEXT, "category": "digital_arrest"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"


# ---------------------------------------------------------------------------
# 5. High overlap with an existing approved pattern -> known
# ---------------------------------------------------------------------------

def test_submit_returns_known_for_high_overlap_with_approved_pattern(monkeypatch):
    fake_pattern = {
        "id": "DA-TEST",
        "category": "digital_arrest",
        "title": "cbi digital arrest warrant call",
        "indicators": ["cbi", "digital arrest", "warrant", "stay on this call"],
        "status": "approved",
    }
    monkeypatch.setattr(
        pattern_store_module, "fetch_approved_patterns", lambda: [fake_pattern]
    )
    monkeypatch.setattr(pattern_store_module, "fetch_pending_by_category", _no_pending)

    # Near-identical word set to the fake pattern's indicators+title (Jaccard
    # overlap 1.0, well above the 0.85 duplicate threshold) while still being
    # a scam-classified, >=20-char message.
    near_duplicate_text = "cbi digital arrest warrant, stay on this call"
    r = client.post("/patterns/submit", json={"text": near_duplicate_text})
    assert r.status_code == 200
    assert r.json()["status"] == "known"


# ---------------------------------------------------------------------------
# 6. Genuinely new pattern -> submitted, and insert_pending_pattern called
# ---------------------------------------------------------------------------

def test_submit_stores_new_nonduplicate_pattern_as_pending(monkeypatch):
    captured = {}

    def _fake_insert_pending(row):
        captured["row"] = row
        return True

    monkeypatch.setattr(pattern_store_module, "fetch_approved_patterns", _no_approved)
    monkeypatch.setattr(pattern_store_module, "fetch_pending_by_category", _no_pending)
    monkeypatch.setattr(pattern_store_module, "insert_pending_pattern", _fake_insert_pending)

    r = client.post("/patterns/submit", json={"text": _SCAM_TEXT})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "submitted"

    assert "row" in captured
    row = captured["row"]
    assert row["submitted_text"] == _SCAM_TEXT
    assert row["detected_category"] == "digital_arrest"
    assert row["status"] == "pending"
    assert row["submitted_via"] == "api"
    assert row["similarity_score"] == 0.0


# ---------------------------------------------------------------------------
# 7. Auto-approval path
# ---------------------------------------------------------------------------

def test_submit_auto_approves_after_three_independent_reports(monkeypatch):
    pending_rows = [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "submitted_text": _SCAM_TEXT,
            "detected_category": "digital_arrest",
            "status": "pending",
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "submitted_text": _SCAM_TEXT,
            "detected_category": "digital_arrest",
            "status": "pending",
        },
    ]

    inserted_scam_pattern = {}
    invalidate_called = {"count": 0}
    incorporated_ids = {}

    def _fake_insert_scam_pattern(row):
        inserted_scam_pattern.update(row)
        return True

    def _fake_invalidate_cache():
        invalidate_called["count"] += 1

    def _fake_mark_incorporated(ids):
        incorporated_ids["ids"] = ids
        return True

    monkeypatch.setattr(pattern_store_module, "fetch_approved_patterns", _no_approved)
    monkeypatch.setattr(
        pattern_store_module, "fetch_pending_by_category", lambda category: pending_rows
    )
    monkeypatch.setattr(pattern_store_module, "insert_scam_pattern", _fake_insert_scam_pattern)
    monkeypatch.setattr(pattern_store_module, "mark_pending_incorporated", _fake_mark_incorporated)
    monkeypatch.setattr(rag_module, "invalidate_cache", _fake_invalidate_cache)

    r = client.post("/patterns/submit", json={"text": _SCAM_TEXT})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "auto_approved"

    assert inserted_scam_pattern, "expected insert_scam_pattern to be called"
    assert re.fullmatch(r"USR-\d{8}-[A-Z0-9]{4}", inserted_scam_pattern["id"])
    assert inserted_scam_pattern["status"] == "auto_approved"
    assert inserted_scam_pattern["submission_count"] == 3
    assert inserted_scam_pattern["category"] == "digital_arrest"

    assert invalidate_called["count"] == 1

    assert incorporated_ids["ids"] == [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ]


# ---------------------------------------------------------------------------
# 8 & 9. GET /patterns/stats
# ---------------------------------------------------------------------------

def test_patterns_stats_returns_known_counts(monkeypatch):
    fake_stats = {
        "approved_count": 22,
        "pending_count": 5,
        "auto_approved_count": 2,
        "last_updated": "2026-08-01T00:00:00+00:00",
    }
    monkeypatch.setattr(pattern_store_module, "get_pattern_stats", lambda: fake_stats)

    r = client.get("/patterns/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["approved_count"] == 22
    assert body["pending_count"] == 5
    assert body["auto_approved_count"] == 2
    assert body["last_updated"] == "2026-08-01T00:00:00+00:00"
    assert "status" not in body or body.get("status") != "unavailable"


def test_patterns_stats_returns_zeros_on_unavailability(monkeypatch):
    monkeypatch.setattr(pattern_store_module, "get_pattern_stats", lambda: None)

    r = client.get("/patterns/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["approved_count"] == 0
    assert body["pending_count"] == 0
    assert body["auto_approved_count"] == 0
    assert body["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 10. GET /trends includes pattern_intelligence
# ---------------------------------------------------------------------------

def test_trends_includes_pattern_intelligence_on_success(monkeypatch):
    fake_stats = {
        "approved_count": 10,
        "pending_count": 1,
        "auto_approved_count": 0,
        "last_updated": "2026-08-01T00:00:00+00:00",
    }
    monkeypatch.setattr(pattern_store_module, "get_pattern_stats", lambda: fake_stats)

    r = client.get("/trends")
    assert r.status_code == 200
    body = r.json()
    assert "pattern_intelligence" in body
    assert body["pattern_intelligence"]["approved_count"] == 10
    # existing shape must remain intact
    for key in ("status", "total_count", "by_scam_type", "last_7_days"):
        assert key in body


def test_trends_includes_pattern_intelligence_unavailable_on_failure(monkeypatch):
    monkeypatch.setattr(pattern_store_module, "get_pattern_stats", lambda: None)

    r = client.get("/trends")
    assert r.status_code == 200
    body = r.json()
    assert body["pattern_intelligence"]["status"] == "unavailable"
    assert body["pattern_intelligence"]["approved_count"] == 0


# ---------------------------------------------------------------------------
# 11. Rate limit: 4th request from same IP within the hour gets 429.
# ---------------------------------------------------------------------------

def test_patterns_submit_rate_limited_after_three_per_hour(monkeypatch):
    monkeypatch.setattr(pattern_store_module, "fetch_approved_patterns", _no_approved)
    monkeypatch.setattr(pattern_store_module, "fetch_pending_by_category", _no_pending)
    monkeypatch.setattr(pattern_store_module, "insert_pending_pattern", lambda row: True)

    headers = {"x-forwarded-for": "203.0.113.55"}
    for i in range(3):
        r = client.post("/patterns/submit", json={"text": _SCAM_TEXT}, headers=headers)
        assert r.status_code == 200, f"request {i} should be allowed"

    r4 = client.post("/patterns/submit", json={"text": _SCAM_TEXT}, headers=headers)
    assert r4.status_code == 429
    assert "Retry-After" in r4.headers
    body = r4.json()
    assert body["error"] == "rate_limited"
    assert "retry_after_seconds" in body


def test_patterns_submit_rate_limit_is_per_ip(monkeypatch):
    monkeypatch.setattr(pattern_store_module, "fetch_approved_patterns", _no_approved)
    monkeypatch.setattr(pattern_store_module, "fetch_pending_by_category", _no_pending)
    monkeypatch.setattr(pattern_store_module, "insert_pending_pattern", lambda row: True)

    headers_a = {"x-forwarded-for": "203.0.113.10"}
    headers_b = {"x-forwarded-for": "203.0.113.11"}
    for _ in range(3):
        r = client.post("/patterns/submit", json={"text": _SCAM_TEXT}, headers=headers_a)
        assert r.status_code == 200
    # A 4th from A is blocked...
    r_blocked = client.post("/patterns/submit", json={"text": _SCAM_TEXT}, headers=headers_a)
    assert r_blocked.status_code == 429
    # ...but B, a different IP, is unaffected.
    r_b = client.post("/patterns/submit", json={"text": _SCAM_TEXT}, headers=headers_b)
    assert r_b.status_code == 200


def test_patterns_stats_endpoint_is_never_rate_limited(monkeypatch):
    """GET /patterns/stats must not be rate-limited even after many calls."""
    monkeypatch.setattr(
        pattern_store_module,
        "get_pattern_stats",
        lambda: {
            "approved_count": 22,
            "pending_count": 0,
            "auto_approved_count": 0,
            "last_updated": "2026-08-24T00:00:00+00:00",
        },
    )
    for _ in range(10):
        r = client.get("/patterns/stats")
        assert r.status_code == 200
