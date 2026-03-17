from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime


class Tool(BaseModel):
    name: str
    category: str
    version: str


class Pipeline(BaseModel):
    project_name: str
    repository: str
    branch: str
    commit_sha: str
    workflow_run_id: str
    scanned_at: datetime


class Taxonomy(BaseModel):
    cwe: Optional[List[str]] = None
    cve: Optional[List[str]] = None
    owasp: Optional[List[str]] = None
    isms_p: Optional[List[str]] = None
    ghsa: Optional[List[str]] = None


class Finding(BaseModel):
    id: str
    normalized_type: str
    title: str
    description: str
    severity: str
    status: str
    confidence: Optional[Dict[str, Any]] = None
    taxonomy: Optional[Taxonomy] = None
    source_finding_id: Optional[str] = None
    correlation_key: Optional[str] = None
    fingerprint: Optional[str] = None


class Location(BaseModel):
    type: str
    path: Optional[str] = None
    url: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    resource_address: Optional[str] = None
    provider: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None
    class_: Optional[str] = None  # class is keyword
    method: Optional[str] = None
    parameter: Optional[str] = None
    endpoint_group: Optional[str] = None


class Evidence(BaseModel):
    summary: Optional[str] = None
    config_snippet: Optional[str] = None
    violated_policy: Optional[Dict[str, Any]] = None
    actual_value: Optional[str] = None
    expected_value: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    advisory_source: Optional[str] = None
    references: Optional[List[str]] = None
    exploit_known: Optional[bool] = None
    kev_listed: Optional[bool] = None
    code_snippet: Optional[str] = None
    dataflow: Optional[Dict[str, Any]] = None
    request: Optional[str] = None
    response: Optional[str] = None
    payload: Optional[str] = None
    reproduction: Optional[List[str]] = None


class Remediation(BaseModel):
    summary: Optional[str] = None
    recommended_action: Optional[str] = None
    fix_example: Optional[str] = None
    patch_available: Optional[bool] = None
    fix_version: Optional[str] = None
    patched_versions: Optional[List[str]] = None
    workaround: Optional[str] = None


class RawDetail(BaseModel):
    check_id: Optional[str] = None
    check_name: Optional[str] = None
    resource: Optional[str] = None
    file: Optional[str] = None
    original_severity: Optional[str] = None
    original_tool_fields: Optional[Dict[str, Any]] = None
    original_rule_id: Optional[str] = None
    alert_id: Optional[str] = None


class Dependency(BaseModel):
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    group: Optional[str] = None
    artifact: Optional[str] = None
    purl: Optional[str] = None
    language: Optional[str] = None
    ecosystem: Optional[str] = None
    dependency_scope: Optional[str] = None
    manifest_file: Optional[str] = None
    lock_file: Optional[str] = None
    dependency_path: Optional[List[str]] = None


# IaC Scan Result
class IaCScanResult(BaseModel):
    schema_version: str
    tool: Tool
    pipeline: Pipeline
    finding: Finding
    location: Location
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


# SCA Scan Result
class SCAScanResult(BaseModel):
    schema_version: str
    pipeline: Pipeline
    tool: Tool
    finding: Finding
    dependency: Dependency
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


# SAST Scan Result
class SASTScanResult(BaseModel):
    schema_version: str
    pipeline: Pipeline
    tool: Tool
    finding: Finding
    location: Location
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


# DAST Scan Result
class DASTScanResult(BaseModel):
    schema_version: str
    pipeline: Pipeline
    tool: Tool
    finding: Finding
    location: Location
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail