from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


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
    cwe: list[str] | None = None
    cve: list[str] | None = None
    owasp: list[str] | None = None
    isms_p: list[str] | None = None
    ghsa: list[str] | None = None


class Finding(BaseModel):
    id: str
    normalized_type: str
    title: str
    description: str
    severity: str
    status: str
    confidence: dict[str, Any] | None = None
    taxonomy: Taxonomy | None = None
    source_finding_id: str | None = None
    correlation_key: str | None = None
    fingerprint: str | None = None


class Location(BaseModel):
    type: str
    path: str | None = None
    url: str | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    resource_address: str | None = None
    provider: str | None = None
    module: str | None = None
    function: str | None = None
    class_: str | None = None
    method: str | None = None
    parameter: str | None = None
    endpoint_group: str | None = None


class Evidence(BaseModel):
    summary: str | None = None
    config_snippet: str | None = None
    violated_policy: dict[str, Any] | None = None
    actual_value: str | None = None
    expected_value: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    published_date: str | None = None
    modified_date: str | None = None
    advisory_source: str | None = None
    references: list[str] | None = None
    exploit_known: bool | None = None
    kev_listed: bool | None = None
    code_snippet: str | None = None
    dataflow: dict[str, Any] | None = None
    request: str | None = None
    response: str | None = None
    payload: str | None = None
    reproduction: list[str] | None = None


class Remediation(BaseModel):
    summary: str | None = None
    recommended_action: str | None = None
    fix_example: str | None = None
    patch_available: bool | None = None
    fix_version: str | None = None
    patched_versions: list[str] | None = None
    workaround: str | None = None


class RawDetail(BaseModel):
    check_id: str | None = None
    check_name: str | None = None
    resource: str | None = None
    file: str | None = None
    original_severity: str | None = None
    original_tool_fields: dict[str, Any] | None = None
    original_rule_id: str | None = None
    alert_id: str | None = None


class Dependency(BaseModel):
    package_name: str | None = None
    package_version: str | None = None
    group: str | None = None
    artifact: str | None = None
    purl: str | None = None
    language: str | None = None
    ecosystem: str | None = None
    dependency_scope: str | None = None
    manifest_file: str | None = None
    lock_file: str | None = None
    dependency_path: list[str] | None = None


class IaCScanResult(BaseModel):
    schema_version: str
    tool: Tool
    pipeline: Pipeline
    finding: Finding
    location: Location
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


class SCAScanResult(BaseModel):
    schema_version: str
    pipeline: Pipeline
    tool: Tool
    finding: Finding
    dependency: Dependency
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


class SASTScanResult(BaseModel):
    schema_version: str
    pipeline: Pipeline
    tool: Tool
    finding: Finding
    location: Location
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


class DASTScanResult(BaseModel):
    schema_version: str
    pipeline: Pipeline
    tool: Tool
    finding: Finding
    location: Location
    evidence: Evidence
    remediation: Remediation
    raw_detail: RawDetail


class ScanCreate(BaseModel):
    repository_url: str | None = None
    branch: str = "main"


class ScanResponse(BaseModel):
    id: int
    status: str
