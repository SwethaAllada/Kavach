"""Kavach FastAPI entrypoint.

This file is deliberately small. The interesting parts are:
  - CORS lock-down driven by `FRONTEND_ORIGIN` (comma-separated allowlist).
  - Per-IP sliding-window rate limiter on /analyze and /webhook.
  - Baseline security headers on every response.

Every middleware is exception-safe: a bug inside a middleware must never
break a legitimate request. The engine layer already never raises out of
`analyze()`; these middlewares extend that invariant to the transport.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.rate_limit import RateLimiter
from routes import analyze, trends, webhook

log = logging.getLogger(__name__)

app = FastAPI(title="Kavach API")

# ---------------------------------------------------------------------------
# CORS — locked to the allowlist parsed from FRONTEND_ORIGIN.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Rate limiter (per-IP sliding window).
# ---------------------------------------------------------------------------
_limiter = RateLimiter(max_per_window=settings.rate_limit_per_min)
_RATE_LIMITED_PATHS = {"/analyze", "/webhook"}


def _client_ip(request: Request) -> str:
    """Best-effort client IP.

    Behind a proxy Render/Fly set X-Forwarded-For to the original IP; the
    first entry is the client, the rest are proxy hops. If the header isn't
    set, fall back to the socket address.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    client = request.client
    return client.host if client else ""


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    try:
        if settings.rate_limit_enabled and request.url.path in _RATE_LIMITED_PATHS:
            ip = _client_ip(request)
            allowed, retry_after = _limiter.check(ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    headers={"Retry-After": str(retry_after)},
                    content={
                        "error": "rate_limited",
                        "message": (
                            "Too many requests. Please slow down and try again "
                            f"in {retry_after} seconds."
                        ),
                        "retry_after_seconds": retry_after,
                    },
                )
    except Exception as e:
        # Never let a bug in the limiter break the app; fail open.
        log.warning("rate limit middleware failed (fail-open): %s", e)

    return await call_next(request)


# ---------------------------------------------------------------------------
# Security headers — applied to every response.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    # Set only if not already present so route handlers can override when
    # they have a reason to (e.g. TwiML replies).
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # API responses are per-user, per-request — never cache.
    response.headers.setdefault("Cache-Control", "no-store")
    # Cheap defense-in-depth: even though we don't serve HTML from the API,
    # some proxies happily render anything as HTML. Disable framing.
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
app.include_router(analyze.router)
app.include_router(webhook.router)
app.include_router(trends.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
