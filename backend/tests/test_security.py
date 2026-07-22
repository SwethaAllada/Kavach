"""Phase 5 security tests: rate limiting + CORS + security headers.

All tests mock the LLM so nothing here needs a live xAI credential. The rate
limiter is exercised at very small thresholds so tests stay fast.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

# Freeze the config BEFORE importing main so the limiter picks a low ceiling.
# We keep the runtime default at 30/min in production, but for tests we
# monkeypatch the singleton limiter to a tighter cap.
from core.config import settings
from core.rate_limit import RateLimiter
from services import classifier as classifier_module
from services.llm import LLMUnavailable


# ---------------------------------------------------------------------------
# Global LLM mock — force the deterministic rules_fallback path so tests don't
# need a live LLM. `classifier.analyze()` still runs end-to-end.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _mock_llm(monkeypatch):
    def _raise(text, grounding=""):
        raise LLMUnavailable("test: llm disabled")
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _raise)
    yield


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


def _client_with_limit(monkeypatch, max_per_window: int):
    """Import main FRESH with a tight rate-limit ceiling, return a TestClient."""
    # Reset any cached module so the limiter singleton is recreated with our value.
    for mod_name in list(sys.modules):
        if mod_name == "main" or mod_name.startswith("routes."):
            sys.modules.pop(mod_name, None)
    monkeypatch.setattr(settings, "rate_limit_per_min", max_per_window)
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    import main  # noqa: F401 — re-imported for side effects
    return TestClient(main.app)


def test_rate_limit_returns_429_when_exceeded(monkeypatch):
    """Load-bearing: over-limit requests get 429 with a Retry-After header."""
    client = _client_with_limit(monkeypatch, max_per_window=3)

    payload = {"text": "hello"}

    ok = [client.post("/analyze", json=payload) for _ in range(3)]
    for r in ok:
        assert r.status_code == 200, r.text

    limited = client.post("/analyze", json=payload)
    assert limited.status_code == 429, limited.text
    body = limited.json()
    assert body["error"] == "rate_limited"
    assert "retry_after_seconds" in body
    assert limited.headers.get("Retry-After"), "Retry-After header missing"


def test_rate_limit_is_per_ip(monkeypatch):
    """Two different X-Forwarded-For clients each get their own budget."""
    client = _client_with_limit(monkeypatch, max_per_window=2)
    payload = {"text": "hello"}

    # Client A burns its budget.
    for _ in range(2):
        r = client.post("/analyze", json=payload, headers={"X-Forwarded-For": "10.0.0.1"})
        assert r.status_code == 200
    r = client.post("/analyze", json=payload, headers={"X-Forwarded-For": "10.0.0.1"})
    assert r.status_code == 429

    # Client B (different IP) is still fine.
    r = client.post("/analyze", json=payload, headers={"X-Forwarded-For": "10.0.0.2"})
    assert r.status_code == 200


def test_rate_limit_disabled_flag(monkeypatch):
    """Flipping KAVACH_RATE_LIMIT_ENABLED=false lets everything through."""
    client = _client_with_limit(monkeypatch, max_per_window=2)
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    payload = {"text": "hello"}
    for _ in range(6):
        r = client.post("/analyze", json=payload)
        assert r.status_code == 200


def test_rate_limit_does_not_touch_health_endpoint(monkeypatch):
    """/health is not in the limited path set."""
    client = _client_with_limit(monkeypatch, max_per_window=1)
    # A single burst that would have limited /analyze.
    for _ in range(10):
        assert client.get("/health").status_code == 200


def test_rate_limiter_fails_open_on_bug(monkeypatch):
    """A bug INSIDE the limiter must not block legit requests."""
    from core import rate_limit

    class Broken(RateLimiter):
        def check(self, ip):
            raise RuntimeError("boom")

    # Reset modules and swap in a broken limiter.
    for mod_name in list(sys.modules):
        if mod_name == "main" or mod_name.startswith("routes."):
            sys.modules.pop(mod_name, None)
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_per_min", 1)
    import main
    monkeypatch.setattr(main, "_limiter", Broken(max_per_window=1))

    client = TestClient(main.app)
    r = client.post("/analyze", json={"text": "hello"})
    # Failed open: legit request must still succeed.
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def _client_with_origins(monkeypatch, origins: list[str]):
    """Rebuild the app with a specific CORS allowlist."""
    for mod_name in list(sys.modules):
        if mod_name == "main" or mod_name.startswith("routes."):
            sys.modules.pop(mod_name, None)
    monkeypatch.setattr(settings, "allowed_origins", origins)
    monkeypatch.setattr(settings, "rate_limit_enabled", False)  # skip rate limits here
    import main  # noqa: F401
    return TestClient(main.app)


def test_cors_allows_configured_origin(monkeypatch):
    """A request from an allowed origin gets the CORS response headers back."""
    allowed = "https://kavach.vercel.app"
    client = _client_with_origins(monkeypatch, [allowed])

    # A CORS preflight is the cleanest way to see the middleware's decision.
    r = client.options(
        "/analyze",
        headers={
            "Origin": allowed,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert r.status_code == 200, r.text
    assert r.headers.get("access-control-allow-origin") == allowed


def test_cors_rejects_disallowed_origin(monkeypatch):
    """A request from an origin NOT on the allowlist gets no CORS header."""
    client = _client_with_origins(monkeypatch, ["https://kavach.vercel.app"])

    r = client.options(
        "/analyze",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    # Starlette's CORSMiddleware handles a disallowed preflight by returning
    # 400 and — more importantly — NOT setting Access-Control-Allow-Origin.
    # The browser is what actually blocks the fetch; the server just has to
    # not vouch for the origin.
    assert r.headers.get("access-control-allow-origin") != "https://evil.example.com"


def test_cors_accepts_multiple_origins(monkeypatch):
    """Comma-separated FRONTEND_ORIGIN is parsed into an allowlist."""
    origins = ["https://kavach.vercel.app", "https://kavach-staging.vercel.app"]
    client = _client_with_origins(monkeypatch, origins)

    for origin in origins:
        r = client.options(
            "/analyze",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert r.status_code == 200
        assert r.headers.get("access-control-allow-origin") == origin


def test_config_parses_comma_separated_frontend_origin(monkeypatch):
    """The config helper normalizes whitespace and trailing slashes."""
    from core.config import _parse_origins
    result = _parse_origins("  https://a.example/,, https://b.example , https://a.example ")
    # Duplicates and trailing slashes gone, order preserved.
    assert result == ["https://a.example", "https://b.example"]


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


def test_security_headers_on_all_responses(monkeypatch):
    client = _client_with_origins(monkeypatch, ["http://localhost:5173"])

    for path in ("/health", "/trends"):
        r = client.get(path)
        assert r.headers.get("X-Content-Type-Options") == "nosniff", f"missing on {path}"
        assert r.headers.get("Referrer-Policy") == "no-referrer", f"missing on {path}"
        assert r.headers.get("Cache-Control") == "no-store", f"missing on {path}"
        assert r.headers.get("X-Frame-Options") == "DENY", f"missing on {path}"

    # Also on POST /analyze.
    r = client.post("/analyze", json={"text": "hello"})
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Cache-Control") == "no-store"
