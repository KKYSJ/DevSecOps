from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    schema_version: Mapped[str | None] = mapped_column(String, nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String, nullable=True)
    tool_category: Mapped[str | None] = mapped_column(String, nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String, nullable=True)
    project_name: Mapped[str | None] = mapped_column(String, nullable=True)
    repository: Mapped[str | None] = mapped_column(String, nullable=True)
    branch: Mapped[str | None] = mapped_column(String, nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String, nullable=True)
    workflow_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    scanned_at: Mapped[DateTime | None] = mapped_column(DateTime, nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String, nullable=True)
    normalized_type: Mapped[str | None] = mapped_column(String, nullable=True)
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str | None] = mapped_column(String, nullable=True)
    final_confidence_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    location_type: Mapped[str | None] = mapped_column(String, nullable=True)
    location_path: Mapped[str | None] = mapped_column(String, nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String, nullable=True)
    resource_name: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)