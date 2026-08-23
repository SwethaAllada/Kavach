"""Tests for services.reputation — URL extraction + PhishTank reputation
checking, the second deterministic signal source alongside the rules engine.

All PhishTank network calls are mocked; no test hits the real feed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from services import reputation as rep


@pytest.fixture(autouse=True)
def _reset_cache():
    """Every test starts with a cold cache so mocks are deterministic."""
    rep._reset_cache_for_tests()
    yield
    rep._reset_cache_for_tests()


def _mock_feed(entries):
    """Return a context manager patching httpx.Client to serve `entries`
    (a list of {"url": ...} dicts) as the PhishTank feed response."""
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = entries

    def _client_factory(*args, **kwargs):
        cm = MagicMock()
        cm.__enter__.return_value.get.return_value = fake_resp
        return cm

    return patch("httpx.Client", side_effect=_client_factory)


# ---------------------------------------------------------------------------
# extract_urls
# ---------------------------------------------------------------------------


def test_extract_urls_finds_http_and_https_urls():
    text = "Click http://phish.example.com/login or https://safe.example.org/x"
    urls = rep.extract_urls(text)
    assert "http://phish.example.com/login" in urls
    assert "https://safe.example.org/x" in urls


def test_extract_urls_finds_bare_suspicious_tld_domains():
    for tld, sample in [
        ("link", "bit-ly.link"),
        ("xyz", "claim-prize.xyz"),
        ("tk", "suspicious.tk"),
        ("ml", "verify-kyc.ml"),
        ("ga", "free-cash.ga"),
        ("cf", "urgent-alert.cf"),
    ]:
        urls = rep.extract_urls(f"Go to {sample} right now")
        assert sample in urls, f"expected {sample!r} (tld={tld}) to be extracted; got {urls}"


def test_extract_urls_ignores_ordinary_domains_without_scheme():
    urls = rep.extract_urls("Visit our site at example.com for more info")
    assert urls == []


def test_extract_urls_returns_empty_list_for_no_urls():
    assert rep.extract_urls("Hi mom, reached office safely.") == []
    assert rep.extract_urls("") == []
    assert rep.extract_urls(None) == []


def test_extract_urls_dedupes_repeated_urls():
    text = "http://phish.example.com/login http://phish.example.com/login"
    assert rep.extract_urls(text) == ["http://phish.example.com/login"]


# ---------------------------------------------------------------------------
# check_url_reputation / get_url_signals — happy path
# ---------------------------------------------------------------------------


def test_check_url_reputation_flags_known_phishing_url():
    with _mock_feed([{"url": "http://phish.example.com/login"}]):
        result = rep.check_url_reputation("http://phish.example.com/login")
    assert result == {
        "url": "http://phish.example.com/login",
        "status": "phishing",
        "source": "PhishTank",
    }


def test_check_url_reputation_marks_unlisted_url_clean():
    with _mock_feed([{"url": "http://phish.example.com/login"}]):
        result = rep.check_url_reputation("http://totally-safe.example.com")
    assert result["status"] == "clean"
    assert result["source"] == "PhishTank"


def test_get_url_signals_returns_empty_list_for_message_with_no_urls():
    assert rep.get_url_signals("Hi mom, reached office safely.") == []


def test_get_url_signals_flags_known_bad_url():
    with _mock_feed([{"url": "http://phish.example.com/login"}]):
        signals = rep.get_url_signals("Please login at http://phish.example.com/login now")
    assert len(signals) == 1
    assert signals[0]["status"] == "phishing"


def test_get_url_signals_caches_feed_across_calls():
    """Second call within the TTL must not re-download."""
    with _mock_feed([{"url": "http://phish.example.com/login"}]) as mocked_client:
        rep.get_url_signals("http://phish.example.com/login")
        rep.get_url_signals("http://phish.example.com/login")
        assert mocked_client.call_count == 1, (
            f"expected exactly one feed download, got {mocked_client.call_count}"
        )


# ---------------------------------------------------------------------------
# Failure handling — never raises, degrades to "unknown"
# ---------------------------------------------------------------------------


def test_get_url_signals_returns_unknown_status_on_network_failure():
    with patch("httpx.Client", side_effect=RuntimeError("network is down")):
        signals = rep.get_url_signals("Please login at http://phish.example.com/login now")
    assert len(signals) == 1
    assert signals[0]["status"] == "unknown"
    assert signals[0]["source"] == "PhishTank"


def test_check_url_reputation_never_raises_on_network_failure():
    with patch("httpx.Client", side_effect=RuntimeError("network is down")):
        result = rep.check_url_reputation("http://phish.example.com/login")
    assert result["status"] == "unknown"


def test_get_url_signals_returns_empty_list_on_unexpected_error():
    """Even a total surprise failure inside get_url_signals must not raise."""
    with patch.object(rep, "extract_urls", side_effect=RuntimeError("boom")):
        assert rep.get_url_signals("anything") == []


def test_check_url_reputation_handles_malformed_feed_response():
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"not": "a list"}  # malformed shape

    def _client_factory(*args, **kwargs):
        cm = MagicMock()
        cm.__enter__.return_value.get.return_value = fake_resp
        return cm

    with patch("httpx.Client", side_effect=_client_factory):
        result = rep.check_url_reputation("http://phish.example.com/login")
    assert result["status"] == "unknown"


def test_check_url_reputation_handles_http_error_status():
    fake_resp = MagicMock()
    fake_resp.status_code = 503
    fake_resp.reason_phrase = "Service Unavailable"

    def _client_factory(*args, **kwargs):
        cm = MagicMock()
        cm.__enter__.return_value.get.return_value = fake_resp
        return cm

    with patch("httpx.Client", side_effect=_client_factory):
        result = rep.check_url_reputation("http://phish.example.com/login")
    assert result["status"] == "unknown"
