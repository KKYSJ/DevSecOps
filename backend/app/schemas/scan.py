from pydantic import BaseModel


class ScanCreate(BaseModel):
    repository_url: str | None = None
    branch: str = "main"


class ScanResponse(BaseModel):
    id: int
    status: str


# 공통 스캔 결과 스키마
class BaseScanResult(BaseModel):
    tool_name: str
    severity: str
    title: str
    description: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    status: str | None = None


# IaC 스캔 결과
class IaCScanResult(BaseScanResult):
    resource: str | None = None
    rule_id: str | None = None


# SCA 스캔 결과
class SCAScanResult(BaseScanResult):
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cve_id: str | None = None


# SAST 스캔 결과
class SASTScanResult(BaseScanResult):
    rule_id: str | None = None
    cwe: str | None = None


# DAST 스캔 결과
class DASTScanResult(BaseScanResult):
    endpoint: str | None = None
    parameter: str | None = None
    cwe: str | None = None