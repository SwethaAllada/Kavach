"""GET /trends — anonymized aggregate view for the Trends dashboard.

Reads via services.store.get_trends(), which itself never raises: on failure
it returns an empty-but-valid shape with status='unavailable'. This route
therefore returns 200 in all cases and the frontend can render a graceful
empty/unavailable state.

Additionally includes a `pattern_intelligence` key (crowd-verified pattern
KB growth stats) sourced from the same shared stats function GET
/patterns/stats uses (routes.patterns.get_stats_response) — never
duplicated, never raises; degrades to the all-zeros/"unavailable" shape on
failure without touching the rest of this response.
"""

from fastapi import APIRouter

from routes import patterns as patterns_route
from services import store

router = APIRouter()


@router.get("/trends")
def trends() -> dict:
    out = store.get_trends()
    try:
        out["pattern_intelligence"] = patterns_route.get_stats_response()
    except Exception:
        # get_stats_response itself never raises, but stay defensive so a
        # bug here can never take down the rest of the /trends response.
        out["pattern_intelligence"] = dict(patterns_route._STATS_FAILURE_SHAPE)
    return out
