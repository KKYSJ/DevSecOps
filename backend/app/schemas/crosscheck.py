from pydantic import BaseModel
from typing import Optional, List


# Crosscheck Dashboard Report
class ToolResult(BaseModel):
    tool_name: str
    status: str
    display_result: str
    finding_id: Optional[str] = None


class LLMJudgement(BaseModel):
    judgement_code: str
    display_label: str
    confidence_level: str
    reason: str
    action_text: str


class Row(BaseModel):
    row_id: str
    target_label: str
    tool_a: ToolResult
    tool_b: ToolResult
    llm_judgement: LLMJudgement


class Section(BaseModel):
    category: str
    section_id: str
    title: str
    tool_a_name: str
    tool_b_name: str
    target_label_name: str
    rows: List[Row]


class SummaryCards(BaseModel):
    high_count: int
    medium_count: int
    low_count: int


class DashboardReport(BaseModel):
    report_id: str
    generated_at: str
    summary_cards: SummaryCards
    sections: List[Section]


class CrosscheckReport(BaseModel):
    schema_version: str
    dashboard_report: DashboardReport