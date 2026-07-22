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
