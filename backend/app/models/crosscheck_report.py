from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class CrosscheckReport(Base):
    __tablename__ = "crosscheck_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    schema_version: Mapped[str | None] = mapped_column(String, nullable=True)
    report_id: Mapped[str | None] = mapped_column(String, unique=True, index=True, nullable=True)
    generated_at: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)