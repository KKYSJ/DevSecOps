from pydantic import BaseModel

class CrossValidationResponse(BaseModel):
    message: str = "not implemented"
from pydantic import BaseModel


class CrosscheckRow(BaseModel):
    category: str
    target: str
    tool_a: str
    tool_b: str
    result: str
    confidence: str
    reason: str | None = None


class CrosscheckSummary(BaseModel):
    total: int
    matched: int
    mismatched: int
    review_needed: int


class CrosscheckReport(BaseModel):
    id: int
    scan_id: int | None = None
    summary: CrosscheckSummary
    rows: list[CrosscheckRow]