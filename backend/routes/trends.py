"""GET /trends — anonymized aggregate view for the Trends dashboard.

Reads via services.store.get_trends(), which itself never raises: on failure
it returns an empty-but-valid shape with status='unavailable'. This route
therefore returns 200 in all cases and the frontend can render a graceful
empty/unavailable state.
"""

from fastapi import APIRouter

from services import store

router = APIRouter()


@router.get("/trends")
def trends() -> dict:
    return store.get_trends()
