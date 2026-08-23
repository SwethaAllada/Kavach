from fastapi import APIRouter
from fastapi.responses import JSONResponse

from models.schemas import AnalyzeRequest, Verdict
from services import store as store_service
from services.classifier import analyze as classifier_analyze
from services.store import AuditStoreUnavailable

router = APIRouter()


@router.post("/analyze", response_model=Verdict)
def analyze(request: AnalyzeRequest) -> Verdict:
    result = classifier_analyze(request.text, language=request.language)
    return Verdict(**result)


@router.get("/case/{case_id}")
def get_case(case_id: str):
    """Legal-admissibility lookup: the audit_log row for `case_id`, proving
    a specific case was analyzed at a given time with a given confidence
    level and matched pattern sources — without ever exposing message text.

    Calls store_service.get_audit_record via the module (not a direct
    name-bound import) so tests can monkeypatch it the same way other
    routes monkeypatch services.store, e.g. store_module.get_audit_record.
    """
    try:
        record = store_service.get_audit_record(case_id)
    except AuditStoreUnavailable:
        return JSONResponse(status_code=503, content={"error": "Audit log unavailable"})
    if record is None:
        return JSONResponse(status_code=404, content={"error": "Case not found"})
    return record
