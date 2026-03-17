from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from sqlalchemy.sql import func
from .database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    schema_version = Column(String)
    tool_name = Column(String)
    tool_category = Column(String)
    tool_version = Column(String)
    project_name = Column(String)
    repository = Column(String)
    branch = Column(String)
    commit_sha = Column(String)
    workflow_run_id = Column(String)
    scanned_at = Column(DateTime)
    finding_id = Column(String)
    normalized_type = Column(String)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    status = Column(String)
    final_confidence_score = Column(Float)
    location_type = Column(String)
    location_path = Column(String)
    resource_type = Column(String)
    resource_name = Column(String)
    raw_data = Column(Text)


class CrosscheckReport(Base):
    __tablename__ = "crosscheck_reports"

    id = Column(Integer, primary_key=True, index=True)
    schema_version = Column(String)
    report_id = Column(String, unique=True, index=True)
    generated_at = Column(String)
    raw_data = Column(Text)


class LLMCrosscheckResult(Base):
    __tablename__ = "llm_crosscheck_results"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String, nullable=False, index=True)
    tool_category = Column(String, nullable=False, index=True)
    workflow_run_id = Column(String, nullable=True, index=True)

    tool_a_name = Column(String, nullable=False)
    tool_b_name = Column(String, nullable=False)

    prompt_name = Column(String, nullable=False)
    llm_model = Column(String, nullable=False)

    tool_a_input_json = Column(Text, nullable=False)
    tool_b_input_json = Column(Text, nullable=False)
    result_json = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())