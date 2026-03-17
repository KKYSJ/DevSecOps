"""
tfsec JSON 출력을 공통 finding 포맷으로 파싱합니다.
IaC 카테고리: results 배열의 각 항목이 하나의 finding입니다.
심각도: CRITICAL/HIGH/MEDIUM/LOW 직접 매핑
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
    "WARNING": "MEDIUM",
}


def _normalize_severity(raw: str) -> str:
    """tfsec 심각도를 공통 포맷으로 변환합니다."""
    return _SEVERITY_MAP.get((raw or "").upper(), "MEDIUM")


def _make_id(tool: str, rule_id: str, file_path: str, line: int | None) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{rule_id}:{file_path}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_resource(result: dict) -> str | None:
    """tfsec result에서 리소스 식별자를 추출합니다."""
    # resource 필드 직접 사용
    resource = result.get("resource") or result.get("affected_resource")
    if resource:
        return resource

    # description에서 리소스 추출 시도
    description = result.get("description") or ""
    location = result.get("location") or {}

    # managed_resource 또는 비슷한 필드
    managed = result.get("managed_resource") or result.get("block") or result.get("attribute")
    if managed:
        return managed

    return None


def parse(raw: dict) -> dict:
    """tfsec JSON 출력을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: tfsec JSON 출력 dict (results 키 포함)

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    results = raw.get("results") or []

    for result in results:
        try:
            rule_id = result.get("rule_id") or result.get("long_id") or ""
            rule_description = result.get("rule_description") or result.get("description") or ""
            raw_severity = result.get("rule_severity") or result.get("severity") or "MEDIUM"
            severity = _normalize_severity(raw_severity)

            location = result.get("location") or {}
            file_path = location.get("filename") or result.get("location", {}).get("filename")
            start_line = location.get("start_line")
            if start_line is not None:
                try:
                    start_line = int(start_line)
                except (ValueError, TypeError):
                    start_line = None

            # finding ID 생성
            finding_id = _make_id("tfsec", rule_id, file_path or "", start_line)

            # 제목 및 설명
            title = rule_description or rule_id
            description = result.get("description") or result.get("rule_description") or ""

            # impact와 resolution을 설명에 포함
            impact = result.get("impact") or ""
            resolution = result.get("resolution") or ""

            if impact and impact not in description:
                description = f"{description}\n영향: {impact}".strip() if description else f"영향: {impact}"
            remediation = resolution if resolution else None

            # 참고 링크
            links = result.get("links") or []
            references = [lnk for lnk in links if isinstance(lnk, str)]

            # 리소스 식별자
            resource = _extract_resource(result)

            # CWE 추출
            cwe_id = None
            for ref in references:
                if "cwe" in ref.lower():
                    import re
                    match = re.search(r"CWE-(\d+)", ref, re.IGNORECASE)
                    if match:
                        cwe_id = f"CWE-{match.group(1)}"
                        break

            findings.append({
                "id": finding_id,
                "tool": "tfsec",
                "category": "IaC",
                "severity": severity,
                "title": title,
                "description": description,
                "rule_id": rule_id,
                "cwe_id": cwe_id,
                "cve_id": None,
                "file_path": file_path,
                "line_number": start_line,
                "url": None,
                "http_method": None,
                "parameter": None,
                "package_name": None,
                "package_version": None,
                "fixed_version": None,
                "cvss_score": None,
                "remediation": remediation,
                "references": references,
                # tfsec 특수 필드 (매처에서 활용)
                "_resource": resource,
            })
        except Exception as e:
            logger.warning("tfsec result 파싱 실패, 건너뜀: %s", e)
            continue

    summary = _make_summary(findings)

    return {
        "tool": "tfsec",
        "category": "IaC",
        "scanned_at": scanned_at,
        "target": None,
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
