from fastapi import APIRouter

from models.schemas import AnalyzeRequest, Verdict
from services.classifier import analyze as classifier_analyze

router = APIRouter()


@router.post("/analyze", response_model=Verdict)
def analyze(request: AnalyzeRequest) -> Verdict:
    result = classifier_analyze(request.text, language=request.language)
    return Verdict(**result)
