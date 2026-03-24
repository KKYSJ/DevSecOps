"""
Checkov JSON 출력 파서

Checkov 실행 명령:
    checkov -d . --output json --output-file checkov-results.json

Checkov JSON 출력 구조:
    {
      "results": {
        "passed_checks": [...],
        "failed_checks": [
          {
            "check_id": "CKV_AWS_17",
            "check": {
              "id": "CKV_AWS_17",
              "name": "Ensure RDS is not publicly accessible"
            },
            "file_path": "/infra/main.tf",
            "file_line_range": [10, 25],
            "resource": "aws_db_instance.postgres",
            "check_result": {"result": "FAILED"},
            "code_block": [...],
            "evaluations": null
          }
        ]
      }
    }

check_id 패턴 기반 severity 분류:
    - encryption, public, exposure, secret, credential 관련 → HIGH
    - logging, monitoring, audit, trail, alert 관련 → MEDIUM
    - 그 외 → LOW
"""

import hashlib
import re
from datetime import datetime, timezone


# check_id 패턴 → severity 매핑 규칙
_HIGH_PATTERNS = [
    r"encrypt",
    r"public",
    r"expos",
    r"secret",
    r"credential",
    r"password",
    r"auth",
    r"ssl",
    r"tls",
    r"iam",
    r"access.key",
    r"bypass",
]

_MEDIUM_PATTERNS = [
    r"log",
    r"monitor",
    r"audit",
    r"trail",
    r"alert",
    r"notif",
    r"backup",
    r"retention",
    r"versioning",
]


def _infer_severity(check_id: str, check_name: str) -> str:
    """check_id와 check_name 기반으로 severity 추론"""
    combined = f"{check_id} {check_name}".lower()

    for pattern in _HIGH_PATTERNS:
        if re.search(pattern, combined):
            return "HIGH"

    for pattern in _MEDIUM_PATTERNS:
        if re.search(pattern, combined):
            return "MEDIUM"

    return "LOW"


def _make_finding_id(check_id: str, file_path: str, resource: str) -> str:
    raw = f"checkov:{check_id}:{file_path}:{resource}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_failed_check(check: dict) -> dict:
    check_id: str = check.get("check_id", "unknown")

    # check 서브딕셔너리에서 이름 추출
    check_meta: dict = check.get("check", {})
    if isinstance(check_meta, dict):
        check_name: str = check_meta.get("name", check_id)
    else:
        check_name = str(check_meta) if check_meta else check_id

    file_path: str = check.get("file_path", "")
    file_line_range: list = check.get("file_line_range", [0, 0])
    resource: str = check.get("resource", "")

    # 시작 라인
    start_line: int | None = None
    if isinstance(file_line_range, (list, tuple)) and len(file_line_range) >= 1:
        try:
            start_line = int(file_line_range[0])
        except (ValueError, TypeError):
            start_line = None

    severity = _infer_severity(check_id, check_name)

    # 설명 구성
    description = f"Checkov check {check_id} failed for resource '{resource}'."
    if check_name and check_name != check_id:
        description = f"{check_name}. Resource: {resource}"

    return {
        "id": _make_finding_id(check_id, file_path, resource),
        "tool": "checkov",
        "category": "IaC",
        "severity": severity,
        "title": check_name[:120] if check_name else check_id,
        "description": description,
        "rule_id": check_id,
        "cwe_id": None,
        "cve_id": None,
        "file_path": file_path or None,
        "line_number": start_line,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": None,
        "package_version": None,
        "fixed_version": None,
        "cvss_score": None,
        "remediation": f"Review and fix {check_id} for {resource}",
        "references": [
            f"https://docs.bridgecrew.io/docs/{check_id.lower()}"
        ],
    }


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class CheckovParser:
    """Checkov JSON 출력을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: checkov --output json 출력 딕셔너리
        Returns:
            공통 스키마 딕셔너리
        """
        # checkov는 단일 결과 또는 리스트로 반환될 수 있음
        # 단일 딕셔너리 형태 처리
        if isinstance(raw, list):
            # 여러 프레임워크 결과 통합
            all_findings = []
            for item in raw:
                results = item.get("results", {})
                failed = results.get("failed_checks", []) if isinstance(results, dict) else []
                for check in failed:
                    all_findings.append(_parse_failed_check(check))
            return {
                "tool": "checkov",
                "category": "IaC",
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "target": None,
                "findings": all_findings,
                "summary": _build_summary(all_findings),
            }

        results = raw.get("results", {})
        if isinstance(results, dict):
            failed_checks: list[dict] = results.get("failed_checks", []) or []
        else:
            failed_checks = []

        findings = [_parse_failed_check(c) for c in failed_checks]

        return {
            "tool": "checkov",
            "category": "IaC",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
