from sqlalchemy import DateTime, Float, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.core.database import Base


class CrossValidation(Base):
    __tablename__ = "cross_validations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_name: Mapped[str] = mapped_column(String(255), default="secureflow")
    commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    phase: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 1 or 2
    category: Mapped[str | None] = mapped_column(String(20), nullable=True)
    tool_a: Mapped[str | None] = mapped_column(String(50), nullable=True)
    tool_b: Mapped[str | None] = mapped_column(String(50), nullable=True)
    judgement_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    llm_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # BLOCK | REVIEW | ALLOW
    gate_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    gate_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
