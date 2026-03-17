"""
Checkov JSON 출력을 공통 finding 포맷으로 파싱합니다.
IaC 카테고리: results.failed_checks 각 항목이 하나의 finding입니다.
심각도: severity가 없을 때 check_id 패턴으로 결정합니다.
  - "encryption" 또는 "public" 또는 "exposure" → HIGH
  - "logging" 또는 "monitoring" 또는 "audit" → MEDIUM
  - 그 외 → LOW
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

# check_id 패턴 기반 심각도 결정 키워드
_HIGH_KEYWORDS = frozenset(["encryption", "encrypt", "public", "exposure", "exposed", "iam", "secret", "credential"])
_MEDIUM_KEYWORDS = frozenset(["logging", "log", "monitoring", "monitor", "audit", "backup", "versioning"])


def _normalize_severity_from_check_id(check_id: str) -> str:
    """check_id 패턴을 분석하여 심각도를 결정합니다."""
    lower_id = (check_id or "").lower()

    for keyword in _HIGH_KEYWORDS:
        if keyword in lower_id:
            return "HIGH"

    for keyword in _MEDIUM_KEYWORDS:
        if keyword in lower_id:
            return "MEDIUM"

    return "LOW"


def _normalize_severity(check: dict, check_id: str) -> str:
    """Checkov 체크에서 심각도를 결정합니다."""
    # severity 필드가 있으면 직접 사용
    severity = check.get("severity") or check.get("check_severity")
    if severity:
        normalized = _SEVERITY_MAP.get(severity.upper())
        if normalized:
            return normalized

    # check_id 패턴으로 결정
    sev = _normalize_severity_from_check_id(check_id)

    # check_id로 결정이 안 된 경우(LOW) check name도 참고
    if sev == "LOW":
        check_name = (check.get("name") or check.get("check_name") or "").lower()
        for keyword in _HIGH_KEYWORDS:
            if keyword in check_name:
                return "HIGH"
        for keyword in _MEDIUM_KEYWORDS:
            if keyword in check_name:
                return "MEDIUM"

    return sev


def _make_id(tool: str, check_id: str, file_path: str, resource: str) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{check_id}:{file_path}:{resource}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_failed_check(failed_check: dict) -> dict | None:
    """단일 failed_check 항목을 finding으로 변환합니다."""
    # check 정보 추출 (중첩 dict 또는 최상위 필드)
    check_info = failed_check.get("check") or {}
    check_id = (
        failed_check.get("check_id")
        or check_info.get("id")
        or check_info.get("check_id")
        or ""
    )
    check_name = (
        failed_check.get("check_name")
        or check_info.get("name")
        or check_info.get("check_name")
        or check_id
    )

    # 심각도 결정
    severity = _normalize_severity(
        {**failed_check, **check_info},
        check_id
    )

    # 파일 경로
    file_path = failed_check.get("file_path") or failed_check.get("repo_file_path") or ""
    # 앞에 "/" 또는 "./" 제거
    if file_path.startswith("/"):
        file_path = file_path.lstrip("/")

    # 라인 범위
    file_line_range = failed_check.get("file_line_range") or []
    start_line = file_line_range[0] if file_line_range else None
    if start_line is not None:
        try:
            start_line = int(start_line)
        except (ValueError, TypeError):
            start_line = None

    # 리소스 식별자
    resource = (
        failed_check.get("resource")
        or failed_check.get("resource_address")
        or failed_check.get("resource_config", {}).get("address")
        or ""
    )

    # finding ID 생성
    finding_id = _make_id("checkov", check_id, file_path, resource)

    # 평가된 키 정보
    check_result = failed_check.get("check_result") or {}
    evaluated_keys = check_result.get("evaluated_keys") or []
    if evaluated_keys:
        keys_str = ", ".join(str(k) for k in evaluated_keys)
        description = f"체크 실패: {check_name}. 평가된 키: {keys_str}"
    else:
        description = f"체크 실패: {check_name}"

    return {
        "id": finding_id,
        "tool": "checkov",
        "category": "IaC",
        "severity": severity,
        "title": check_name,
        "description": description,
        "rule_id": check_id,
        "cwe_id": None,
        "cve_id": None,
        "file_path": file_path if file_path else None,
        "line_number": start_line,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": None,
        "package_version": None,
        "fixed_version": None,
        "cvss_score": None,
        "remediation": check_info.get("guideline") or check_info.get("fix") or None,
        "references": [],
        # checkov 특수 필드 (매처에서 활용)
        "_resource": resource,
    }


def parse(raw: dict) -> dict:
    """Checkov JSON 출력을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: Checkov JSON 출력 dict

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    # Checkov 결과는 results.failed_checks 또는 최상위 배열일 수 있습니다
    results = raw.get("results") or {}

    if isinstance(results, dict):
        failed_checks = results.get("failed_checks") or []
    elif isinstance(results, list):
        # 결과가 직접 배열로 오는 경우
        failed_checks = results
    else:
        failed_checks = []

    # 최상위에 failed_checks가 있는 경우도 처리
    if not failed_checks:
        failed_checks = raw.get("failed_checks") or []

    # 다중 결과 파일 형식 처리 (배열 of result objects)
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                sub_results = item.get("results") or {}
                if isinstance(sub_results, dict):
                    failed_checks.extend(sub_results.get("failed_checks") or [])

    for failed_check in failed_checks:
        try:
            finding = _parse_failed_check(failed_check)
            if finding:
                findings.append(finding)
        except Exception as e:
            logger.warning("Checkov failed_check 파싱 실패, 건너뜀: %s", e)
            continue

    summary = _make_summary(findings)

    return {
        "tool": "checkov",
        "category": "IaC",
        "scanned_at": scanned_at,
        "target": raw.get("repo_id") or None,
        "findings": findings,
        "summary": summary,
    }


def _make_summary(findings: list) -> dict:
    """findings 목록에서 severity별 카운트를 집계합니다."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "total": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
    }
