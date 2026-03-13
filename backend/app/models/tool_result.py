from sqlalchemy import Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.core.database import Base


class ToolResult(Base):
    __tablename__ = "tool_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(50), default="ok")
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
