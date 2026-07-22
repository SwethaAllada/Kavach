from fastapi import APIRouter

router = APIRouter()


@router.get("/trends")
def trends() -> dict:
    return {
        "total_analyzed": 0,
        "scam_type_counts": {},
        "risk_avg": 0,
    }
