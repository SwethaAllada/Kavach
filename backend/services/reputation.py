"""URL reputation checking — a second deterministic signal source alongside
the rules engine, distinct from the LLM.

Uses PhishTank's free public feed (https://data.phishtank.com/data/online-valid.json)
to flag known phishing URLs found in a message.

Design constraints:
  - The feed is a large JSON file. It is downloaded at most once per
    _CACHE_TTL_SECONDS (1 hour) and cached in memory; every call within the
    TTL is a plain dict/set lookup.
  - Never raises, never blocks the request path for long: a 5s timeout on
    the download, and any failure (timeout, network error, bad JSON) is
    swallowed and treated as "unknown" — the classifier's decision is
    unaffected either way.
  - No new HTTP library: reuses `httpx`, already a project dependency.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.json"
_DOWNLOAD_TIMEOUT_S = 5.0
_CACHE_TTL_SECONDS = 60 * 60  # 1 hour

# Bare domains (no http/https prefix) using these TLDs are treated as
# suspicious-enough-to-check even without an explicit scheme — these TLDs
# are disproportionately used by free/throwaway-domain phishing campaigns.
_SUSPICIOUS_TLDS = ("link", "xyz", "tk", "ml", "ga", "cf")

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)

# Bare domain, e.g. "verify-kyc.xyz" or "bit-ly.link/abc123" — a dot-separated
# label sequence ending in one of the suspicious TLDs, not already preceded
# by "://" (that case is already covered by _URL_RE above). The optional
# path (if present) is captured too, so "bit-ly.link/abc123" round-trips
# whole rather than being truncated to just the domain.
_BARE_DOMAIN_RE = re.compile(
    r"(?<!://)(?<![\w.])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.(?:" + "|".join(_SUSPICIOUS_TLDS) + r")(?:/\S*)?)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def extract_urls(text: str) -> list[str]:
    """Return the list of URLs found in `text`: explicit http(s):// URLs plus
    bare domains using a suspicious TLD (e.g. "claim-prize.xyz") even without
    a scheme. Never raises; returns [] on empty/invalid input."""
    if not text or not isinstance(text, str):
        return []
    try:
        urls = list(_URL_RE.findall(text))
        # Strip a scheme'd URL's match so we don't also match its bare-domain
        # substring twice; findall on the full text against _BARE_DOMAIN_RE
        # already excludes "://"-preceded matches via the negative lookbehind.
        bare = [m.group(1) for m in _BARE_DOMAIN_RE.finditer(text)]
        seen: set[str] = set()
        result: list[str] = []
        for u in urls + bare:
            if u not in seen:
                seen.add(u)
                result.append(u)
        return result
    except Exception as e:  # pragma: no cover - defensive
        log.warning("extract_urls failed (swallowed): %s", e)
        return []


def _domain_of(url: str) -> str:
    """Best-effort hostname extraction, lowercased, without a scheme."""
    try:
        candidate = url if "://" in url else f"http://{url}"
        host = urlparse(candidate).netloc.lower()
        # Strip a userinfo@ prefix and :port suffix if present.
        host = host.split("@")[-1].split(":")[0]
        return host
    except Exception:
        return url.lower()


# ---------------------------------------------------------------------------
# PhishTank feed — in-memory cache with a 1-hour TTL
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()
_cached_urls: set[str] = set()
_cached_domains: set[str] = set()
_cache_fetched_at: float = 0.0


def _cache_is_warm() -> bool:
    return (time.monotonic() - _cache_fetched_at) < _CACHE_TTL_SECONDS and (
        _cached_urls or _cached_domains
    )


def _download_feed() -> Optional[tuple[set[str], set[str]]]:
    """Download and parse the PhishTank feed. Returns (urls, domains) sets,
    or None on any failure (timeout, network error, bad JSON shape)."""
    try:
        with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_S) as client:
            resp = client.get(PHISHTANK_FEED_URL)
            if resp.status_code >= 300:
                log.warning(
                    "PhishTank feed download failed: HTTP %s", resp.status_code
                )
                return None
            data = resp.json()
    except Exception as e:
        log.warning("PhishTank feed download error (falling back to unknown): %s", e)
        return None

    if not isinstance(data, list):
        log.warning("PhishTank feed: unexpected response shape (not a list)")
        return None

    urls: set[str] = set()
    domains: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if isinstance(url, str) and url:
            urls.add(url)
            domains.add(_domain_of(url))
    return urls, domains


def _refresh_cache_if_needed() -> None:
    global _cached_urls, _cached_domains, _cache_fetched_at
    with _cache_lock:
        if _cache_is_warm():
            return
        result = _download_feed()
        if result is None:
            # Leave any existing (possibly stale) cache in place rather than
            # clearing it — a slightly-stale cache is still useful signal,
            # and this also means a transient failure right after a
            # successful refresh doesn't throw away good data.
            return
        _cached_urls, _cached_domains = result
        _cache_fetched_at = time.monotonic()


def _reset_cache_for_tests() -> None:
    """Test-only helper: force the next check_url_reputation call to
    re-download rather than use a warm cache."""
    global _cached_urls, _cached_domains, _cache_fetched_at
    with _cache_lock:
        _cached_urls = set()
        _cached_domains = set()
        _cache_fetched_at = 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_url_reputation(url: str) -> dict:
    """Check `url` against the cached PhishTank feed.

    Returns {"url": url, "status": "phishing"|"clean"|"unknown",
             "source": "PhishTank"}. Never raises: any failure to obtain a
    fresh-enough feed results in status "unknown" rather than an exception.
    """
    try:
        _refresh_cache_if_needed()
        if not _cache_is_warm():
            return {"url": url, "status": "unknown", "source": "PhishTank"}

        if url in _cached_urls or _domain_of(url) in _cached_domains:
            return {"url": url, "status": "phishing", "source": "PhishTank"}
        return {"url": url, "status": "clean", "source": "PhishTank"}
    except Exception as e:  # pragma: no cover - defensive
        log.warning("check_url_reputation failed (swallowed): %s", e)
        return {"url": url, "status": "unknown", "source": "PhishTank"}


def get_url_signals(text: str) -> list[dict]:
    """Extract URLs from `text` and check each against PhishTank.

    Never raises — returns [] on any error, including "no URLs found".
    Fast when the PhishTank cache is warm (dict/set lookups only).
    """
    try:
        urls = extract_urls(text)
        if not urls:
            return []
        return [check_url_reputation(u) for u in urls]
    except Exception as e:
        log.warning("get_url_signals failed (swallowed): %s", e)
        return []
