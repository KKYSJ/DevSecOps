from sqlalchemy import DateTime, Float, Integer, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.core.database import Base


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_name: Mapped[str] = mapped_column(String(255), default="secureflow")
    commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    branch: Mapped[str] = mapped_column(String(100), default="main")
    # scanning_phase1 | scanning_phase2 | completed | blocked
    status: Mapped[str] = mapped_column(String(50), default="scanning_phase1")
    # BLOCK | REVIEW | ALLOW — analyze 호출 시 확정
    gate_result: Mapped[str | None] = mapped_column(String(20), nullable=True)
    gate_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    scan_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
