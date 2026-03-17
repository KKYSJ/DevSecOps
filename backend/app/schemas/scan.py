from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any


class ScanCreate(BaseModel):
    repository_url: str | None = None
    branch: str = "main"


class ScanResponse(BaseModel):
    id: int
    status: str


class ToolInfo(BaseModel):
    name: str
    category: str
    version: Optional[str] = None


class PipelineInfo(BaseModel):
    project_name: str
    repository: str
    branch: str
    commit_sha: str
    workflow_run_id: str
    scanned_at: datetime


class ConfidenceInfo(BaseModel):
    tool_confidence: Optional[str] = None
    correlation_confidence: Optional[str] = None
    llm_confidence: Optional[str] = None
    final_confidence_score: Optional[float] = None


class TaxonomyInfo(BaseModel):
    cwe: list[Any] = []
    cve: list[Any] = []
    owasp: list[Any] = []
    isms_p: list[Any] = []


class FindingInfo(BaseModel):
    id: str
    normalized_type: str
    title: str
    description: Optional[str] = None
    severity: str
    confidence: Optional[ConfidenceInfo] = None
    status: str
    taxonomy: Optional[TaxonomyInfo] = None


class LocationInfo(BaseModel):
    type: str
    path: Optional[str] = None
    url: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    resource_address: Optional[str] = None
    provider: Optional[str] = None
    module: Optional[str] = None


class EvidencePolicy(BaseModel):
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None


class EvidenceInfo(BaseModel):
    summary: Optional[str] = None
    config_snippet: Optional[str] = None
    violated_policy: Optional[EvidencePolicy] = None
    actual_value: Optional[str] = None
    expected_value: Optional[str] = None


class RemediationInfo(BaseModel):
    summary: Optional[str] = None
    recommended_action: Optional[str] = None
    fix_example: Optional[str] = None
    patch_available: Optional[bool] = None


class RawDetailInfo(BaseModel):
    check_id: Optional[str] = None
    check_name: Optional[str] = None
    resource: Optional[str] = None
    file: Optional[str] = None
    original_severity: Optional[str] = None


class IaCScanResult(BaseModel):
    schema_version: str
    tool: ToolInfo
    pipeline: PipelineInfo
    finding: FindingInfo
    location: LocationInfo
    evidence: Optional[EvidenceInfo] = None
    remediation: Optional[RemediationInfo] = None
    raw_detail: Optional[RawDetailInfo] = None


class SCAScanResult(BaseModel):
    schema_version: str
    tool: ToolInfo
    pipeline: PipelineInfo
    finding: FindingInfo
    evidence: Optional[EvidenceInfo] = None
    remediation: Optional[RemediationInfo] = None
    raw_detail: Optional[RawDetailInfo] = None


class SASTScanResult(BaseModel):
    schema_version: str
    tool: ToolInfo
    pipeline: PipelineInfo
    finding: FindingInfo
    location: LocationInfo
    evidence: Optional[EvidenceInfo] = None
    remediation: Optional[RemediationInfo] = None
    raw_detail: Optional[RawDetailInfo] = None


class DASTScanResult(BaseModel):
    schema_version: str
    tool: ToolInfo
    pipeline: PipelineInfo
    finding: FindingInfo
    location: LocationInfo
    evidence: Optional[EvidenceInfo] = None
    remediation: Optional[RemediationInfo] = None
    raw_detail: Optional[RawDetailInfo] = None