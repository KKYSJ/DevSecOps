"""
tfsec JSON 출력 파서

tfsec 실행 명령:
    tfsec . --format json --out tfsec-results.json

tfsec JSON 출력 구조:
    {
      "results": [
        {
          "rule_id": "aws-rds-enable-iam-authentication",
          "rule_description": "RDS IAM auth disabled",
          "rule_severity": "HIGH",
          "location": {"filename": "main.tf", "start_line": 42},
          "description": "...",
          "links": ["https://..."],
          "impact": "...",
          "resolution": "..."
        }
      ]
    }

tfsec severity → 공통 severity 매핑:
    CRITICAL → CRITICAL
    HIGH     → HIGH
    MEDIUM   → MEDIUM
    LOW      → LOW
    INFO     → INFO
"""

import hashlib
from datetime import datetime, timezone


_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.upper(), "MEDIUM")


def _make_finding_id(rule_id: str, filename: str, line: int) -> str:
    raw = f"tfsec:{rule_id}:{filename}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_result(result: dict) -> dict:
    rule_id: str = result.get("rule_id", "unknown")
    rule_desc: str = result.get("rule_description", rule_id)
    severity_raw: str = result.get("rule_severity", "MEDIUM")
    description: str = result.get("description", "")
    links: list = result.get("links", [])
    impact: str = result.get("impact", "")
    resolution: str = result.get("resolution", "")

    location: dict = result.get("location", {})
    filename: str = location.get("filename", "")
    start_line: int = location.get("start_line", 0)

    # 설명 합성: impact가 있으면 포함
    full_desc = description
    if impact:
        full_desc = f"{description}\nImpact: {impact}" if description else f"Impact: {impact}"

    # 수정 방법: resolution 필드
    remediation = resolution or None

    return {
        "id": _make_finding_id(rule_id, filename, start_line),
        "tool": "tfsec",
        "category": "IaC",
        "severity": _normalize_severity(severity_raw),
        "title": rule_desc[:120] if rule_desc else rule_id,
        "description": full_desc,
        "rule_id": rule_id,
        "cwe_id": None,
        "cve_id": None,
        "file_path": filename or None,
        "line_number": start_line or None,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": None,
        "package_version": None,
        "fixed_version": None,
        "cvss_score": None,
        "remediation": remediation,
        "references": links,
    }


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class TfsecParser:
    """tfsec JSON 출력을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: tfsec --format json 출력 딕셔너리
        Returns:
            공통 스키마 딕셔너리
        """
        results: list[dict] = raw.get("results", [])
        # results가 None인 경우 처리
        if results is None:
            results = []

        findings = [_parse_result(r) for r in results]

        return {
            "tool": "tfsec",
            "category": "IaC",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
