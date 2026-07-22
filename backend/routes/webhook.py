from fastapi import APIRouter

router = APIRouter()


@router.post("/webhook")
def webhook() -> dict:
    return {"status": "stub"}
