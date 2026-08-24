from pydantic import BaseModel


class AnalyzeRequest(BaseModel):
    text: str
    language: str | None = None


class Verdict(BaseModel):
    scam_type: str
    risk: int
    confidence: float
    decision_source: str
    fallback_used: bool
    signals: list[str]
    matched_patterns: list
    artifacts: dict
    explanation: str
    recommended_action: str
    report: dict
    detected_language: str
    case_id: str


class ImageVerdict(Verdict):
    """Response shape for POST /analyze-image: everything Verdict has, plus
    the OCR'd message text and sender so the UI can show the user what was
    actually read from their screenshot before acting on the verdict."""

    extracted_text: str
    extracted_sender: str | None = None


class PatternSubmitRequest(BaseModel):
    """Request body for POST /patterns/submit — a user voluntarily
    contributing a scam-message example to the crowd-verified KB. `text`
    length (20-500 chars after stripping) and `source` length (<=100 chars)
    are validated explicitly in the route handler, not here, so the handler
    can strip() before checking length."""

    text: str
    category: str | None = None
    source: str | None = None
