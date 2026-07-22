"""Per-IP sliding-window rate limiter.

Dependency-free (no Redis, no third-party libs). Suitable for a single-process
demo backend on Render / Fly.io. If we ever scale to multiple workers we'll
need a shared store, but for the pitch this is enough.

Design:
  - Sliding 60-second window keyed by client IP.
  - Bounded memory: entries older than the window are pruned lazily on every
    request, and the map size is hard-capped.
  - Thread-safe (uvicorn workers may share this state).
  - Fail-open: any exception inside the limiter itself is swallowed and the
    request is allowed through. A misbehaving limiter must never block a
    legitimate user.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque

log = logging.getLogger(__name__)

_WINDOW_SECONDS = 60.0
_MAX_TRACKED_IPS = 10_000  # hard ceiling on memory


class RateLimiter:
    """Sliding-window per-IP rate limiter. Instantiate once at app startup."""

    def __init__(self, max_per_window: int, window_seconds: float = _WINDOW_SECONDS):
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, Deque[float]] = {}

    def check(self, ip: str) -> tuple[bool, int]:
        """Return `(allowed, retry_after_seconds)`.

        - `allowed=True`  -> request may proceed. `retry_after_seconds` is 0.
        - `allowed=False` -> caller should return 429. `retry_after_seconds`
          is how long until the OLDEST hit in the current window falls out.
        """
        if not ip:
            # If we can't identify the client, do NOT rate-limit — better to
            # let a broken proxy through than to lock out real users.
            return True, 0

        now = time.monotonic()
        cutoff = now - self.window_seconds

        try:
            with self._lock:
                # Prune the IP's queue.
                dq = self._hits.get(ip)
                if dq is None:
                    # If the tracking map is at its cap, evict a random-ish
                    # entry (the first key iterated) to keep memory bounded.
                    if len(self._hits) >= _MAX_TRACKED_IPS:
                        for old_key in self._hits:
                            del self._hits[old_key]
                            break
                    dq = deque()
                    self._hits[ip] = dq
                else:
                    while dq and dq[0] < cutoff:
                        dq.popleft()

                if len(dq) >= self.max_per_window:
                    # Reject. Compute how long until the oldest hit expires.
                    oldest = dq[0]
                    retry_after = max(1, int(self.window_seconds - (now - oldest)) + 1)
                    return False, retry_after

                dq.append(now)
                return True, 0
        except Exception as e:
            log.warning("rate limiter check failed (fail-open): %s", e)
            return True, 0

    def clear(self) -> None:
        """Reset all tracked IPs. Used by tests."""
        with self._lock:
            self._hits.clear()
