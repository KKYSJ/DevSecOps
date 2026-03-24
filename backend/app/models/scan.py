from sqlalchemy import DateTime, Integer, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tool: Mapped[str] = mapped_column(String(50), default="unknown")
    category: Mapped[str | None] = mapped_column(String(20), nullable=True)
    project_name: Mapped[str] = mapped_column(String(255), default="secureflow")
    commit_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # received | processing | done | failed
    status: Mapped[str] = mapped_column(String(50), default="received")
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
