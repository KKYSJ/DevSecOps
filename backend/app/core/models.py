from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

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