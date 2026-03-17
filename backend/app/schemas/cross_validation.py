from typing import Any

from pydantic import BaseModel


class CrossValidationResponse(BaseModel):
    message: str = "not implemented"


class ToolResult(BaseModel):
    tool_name: str | None = None
    status: str | None = None
    display_result: str | None = None
    finding_id: str | None = None


class LLMJudgement(BaseModel):
    judgement_code: str
    display_label: str
    confidence_level: str
    reason: str
    action_text: str


class CrosscheckRow(BaseModel):
    row_id: str
    target_label: str
    tool_a: ToolResult
    tool_b: ToolResult | None = None
    llm_judgement: LLMJudgement
    severity: str | None = None
    metadata: dict[str, Any] | None = None


class CrosscheckSection(BaseModel):
    category: str
    section_id: str
    title: str
    tool_a_name: str
    tool_b_name: str | None = None
    target_label_name: str
    rows: list[CrosscheckRow]


class SummaryCards(BaseModel):
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class DashboardReport(BaseModel):
    report_id: str
    generated_at: str
    summary_cards: SummaryCards
    sections: list[CrosscheckSection]


class CrosscheckReport(BaseModel):
    schema_version: str
    dashboard_report: DashboardReport
