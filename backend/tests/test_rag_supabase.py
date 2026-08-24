"""Tests for services.rag's Supabase-backed migration (Part B).

retrieve()'s public contract must stay byte-identical to the pre-migration
JSON-only behavior when Supabase is unavailable, and must actually use
Supabase-sourced entries when a fetch succeeds. All Supabase calls are
mocked; no test hits the real network.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from services import rag


@pytest.fixture(autouse=True)
def _reset_rag_cache():
    """Every test starts with a cold Supabase cache so mocks are deterministic
    and tests don't leak state into each other."""
    rag._supabase_cache["ts"] = None
    rag._supabase_cache["entries"] = None
    yield
    rag._supabase_cache["ts"] = None
    rag._supabase_cache["entries"] = None


def _mock_supabase_get(payload, status_code=200):
    """Return a context manager patching httpx.Client to serve `payload` as
    the scam_patterns GET response, mirroring test_reputation.py's
    _mock_feed helper pattern."""
    fake_resp = MagicMock()
    fake_resp.status_code = status_code
    fake_resp.reason_phrase = "OK" if status_code < 300 else "Error"
    fake_resp.json.return_value = payload

    def _client_factory(*args, **kwargs):
        cm = MagicMock()
        cm.__enter__.return_value.get.return_value = fake_resp
        return cm

    return patch("httpx.Client", side_effect=_client_factory)


def _configure_supabase(monkeypatch):
    from core.config import settings
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co")
    monkeypatch.setattr(settings, "supabase_service_key", "fake-service-key")


# ---------------------------------------------------------------------------
# 1. retrieve() returns results sourced from Supabase when it's available.
# ---------------------------------------------------------------------------

def test_retrieve_returns_results_from_supabase_patterns(monkeypatch):
    _configure_supabase(monkeypatch)
    fake_rows = [
        {
            "id": "SUP-01",
            "category": "digital_arrest",
            "title": "Fake CBI digital arrest video call scam",
            "indicators": ["digital arrest", "cbi officer", "stay on the call"],
            "why_scam": "Law enforcement never arrests you over a video call.",
            "safe_action": "Hang up. Report to 1930.",
            "source": "test fixture",
            "languages": ["en"],
            "status": "approved",
        }
    ]
    with _mock_supabase_get(fake_rows):
        hits = rag.retrieve("This is a digital arrest, stay on the call, cbi officer speaking")
    assert len(hits) >= 1
    assert any(h["id"] == "SUP-01" for h in hits)
    assert any(h["category"] == "digital_arrest" for h in hits)


def test_get_kb_reflects_supabase_entries_when_available(monkeypatch):
    _configure_supabase(monkeypatch)
    fake_rows = [
        {
            "id": "SUP-02",
            "category": "other",
            "title": "Test entry",
            "indicators": ["foo bar"],
            "why_scam": "why",
            "safe_action": "action",
            "source": "src",
            "languages": ["en"],
            "status": "approved",
        }
    ]
    with _mock_supabase_get(fake_rows):
        kb = rag.get_kb()
    assert len(kb) == 1
    assert kb[0]["id"] == "SUP-02"
    assert kb[0]["indicators"] == ["foo bar"]


# ---------------------------------------------------------------------------
# 2. Falls back to the JSON file identically when Supabase is unavailable.
# ---------------------------------------------------------------------------

def test_retrieve_falls_back_to_json_kb_when_supabase_unconfigured():
    # Supabase intentionally left unconfigured (default test settings may or
    # may not have real creds; force unconfigured explicitly regardless).
    with patch.object(rag, "_is_configured", return_value=False):
        hits = rag.retrieve(
            "This is CBI. A parcel in your name has narcotics. Stay on this "
            "Skype call, do not tell anyone, transfer for verification."
        )
    assert len(hits) >= 1
    assert any(h["category"] == "digital_arrest" for h in hits)


def test_retrieve_matches_pre_migration_json_only_behavior_when_supabase_fails(monkeypatch):
    """The known digital_arrest hit (test_retrieval_hits_relevant_patterns_for_digital_arrest
    in test_analyze.py) must still fire identically when Supabase errors out."""
    _configure_supabase(monkeypatch)
    text = (
        "This is CBI. A parcel in your name has narcotics. Stay on this "
        "Skype call, do not tell anyone, transfer for verification."
    )

    # Supabase fetch raises -> _load_from_supabase returns None -> fallback.
    with patch("httpx.Client", side_effect=RuntimeError("network is down")):
        hits_via_fallback = rag.retrieve(text, top_k=3)

    # Direct call against the JSON-only path for comparison.
    json_kb = rag._load_kb()
    text_norm = rag._normalize(text)
    text_tokens = set(rag._tokenize(text))
    scored = []
    for entry in json_kb:
        raw, matched = rag._score_entry(text_norm, text_tokens, entry)
        sim = rag._normalize_score(raw)
        if sim >= 0.15:
            scored.append((sim, matched, entry))
    scored.sort(key=lambda x: x[0], reverse=True)
    expected = [
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
        for sim, matched, entry in scored[:3]
    ]

    assert hits_via_fallback == expected
    assert any(h["category"] == "digital_arrest" for h in hits_via_fallback)


def test_retrieve_on_benign_text_still_returns_nothing_when_supabase_fails(monkeypatch):
    _configure_supabase(monkeypatch)
    with patch("httpx.Client", side_effect=RuntimeError("network is down")):
        hits = rag.retrieve("Hi mom, reached office safely. Will call after lunch.")
    assert hits == []


def test_stale_cache_preferred_over_discarding_on_transient_failure(monkeypatch):
    """On a failed refresh, a previously-warm cache must be kept rather than
    replaced with the JSON fallback."""
    _configure_supabase(monkeypatch)
    good_rows = [
        {
            "id": "SUP-03",
            "category": "other",
            "title": "cached entry",
            "indicators": ["cached indicator phrase"],
            "why_scam": "why",
            "safe_action": "action",
            "source": "src",
            "languages": ["en"],
            "status": "approved",
        }
    ]
    with _mock_supabase_get(good_rows):
        first = rag._get_entries()
    assert first[0]["id"] == "SUP-03"

    # Force the cache to look expired, then fail the refresh — the stale
    # cache should still be returned, not the JSON fallback.
    rag._supabase_cache["ts"] = 0.0
    with patch("httpx.Client", side_effect=RuntimeError("network is down")):
        second = rag._get_entries()
    assert second[0]["id"] == "SUP-03"


def test_invalidate_cache_forces_reload_on_next_call(monkeypatch):
    _configure_supabase(monkeypatch)
    rows_v1 = [{
        "id": "SUP-04", "category": "other", "title": "v1",
        "indicators": [], "why_scam": "", "safe_action": "", "source": "",
        "languages": ["en"],
    }]
    rows_v2 = [{
        "id": "SUP-05", "category": "other", "title": "v2",
        "indicators": [], "why_scam": "", "safe_action": "", "source": "",
        "languages": ["en"],
    }]

    with _mock_supabase_get(rows_v1):
        first = rag._get_entries()
    assert first[0]["id"] == "SUP-04"

    # Without invalidation, the warm cache would be reused (no new fetch).
    rag.invalidate_cache()

    with _mock_supabase_get(rows_v2):
        second = rag._get_entries()
    assert second[0]["id"] == "SUP-05"
