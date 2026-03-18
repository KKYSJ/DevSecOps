"""
SonarQube API /api/issues/search 응답을 공통 finding 포맷으로 파싱합니다.
심각도 매핑: BLOCKER→CRITICAL, CRITICAL→HIGH, MAJOR→MEDIUM, MINOR→LOW, INFO→INFO
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "INFO",
}

_VALID_STATUSES = {"OPEN", "REOPENED", "CONFIRMED"}


def _normalize_severity(raw: str) -> str:
    """SonarQube 심각도를 공통 포맷으로 변환합니다."""
    return _SEVERITY_MAP.get((raw or "").upper(), "MEDIUM")


def _make_id(tool: str, rule_id: str, file_path: str, line: int | None) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{rule_id}:{file_path}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_file_path(issue: dict) -> str | None:
    """SonarQube issue에서 파일 경로를 추출합니다.
    components 배열의 path 필드를 우선 사용하고, 없으면 component 문자열에서 추출합니다.
    """
    component_key = issue.get("component", "")

    # components 배열에서 해당 컴포넌트의 path를 찾습니다
    components = issue.get("_components", [])
    for comp in components:
        if comp.get("key") == component_key:
            path = comp.get("path")
            if path:
                return path

    # component 문자열에서 경로 추출 (예: "project:src/main.py" → "src/main.py")
    if ":" in component_key:
        return component_key.split(":", 1)[1]

    return component_key if component_key else None


def _extract_cwe(rule_id: str, tags: list) -> str | None:
    """rule_id 또는 태그에서 CWE ID를 추출합니다."""
    # 태그에서 CWE 추출 (예: "cwe:89")
    for tag in (tags or []):
        if tag.lower().startswith("cwe:"):
            cwe_num = tag.split(":", 1)[1]
            return f"CWE-{cwe_num}"
    return None


def parse(raw: dict) -> dict:
    """SonarQube API 응답을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: SonarQube /api/issues/search 응답 dict

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    # issues 목록 파싱
    issues = raw.get("issues", [])

    # components 정보를 issue에 주입 (파일 경로 추출용)
    components = raw.get("components", [])
    components_by_key = {c.get("key", ""): c for c in components}

    for issue in issues:
        try:
            # 활성 상태 이슈만 처리
            status = issue.get("status", "OPEN").upper()
            if status not in _VALID_STATUSES:
                continue

            # components 정보 임시 주입
            issue["_components"] = components

            rule_id = issue.get("rule", "")
            raw_severity = issue.get("severity", "MAJOR")
            severity = _normalize_severity(raw_severity)

            # 파일 경로 추출
            file_path = _extract_file_path(issue)

            # 라인 번호
            line_number = issue.get("line") or issue.get("textRange", {}).get("startLine")
            if line_number is not None:
                try:
                    line_number = int(line_number)
                except (ValueError, TypeError):
                    line_number = None

            # finding ID 생성
            finding_id = _make_id("sonarqube", rule_id, file_path or "", line_number)

            # 제목 및 설명
            title = issue.get("message", rule_id) or rule_id
            description = issue.get("message", "")

            # CWE 추출
            tags = issue.get("tags", [])
            cwe_id = _extract_cwe(rule_id, tags)

            # 수정 방법
            remediation = None
            effort = issue.get("effort") or issue.get("debt")
            if effort:
                remediation = f"예상 수정 소요 시간: {effort}"

            findings.append({
                "id": finding_id,
                "tool": "sonarqube",
                "category": "SAST",
                "severity": severity,
                "title": title,
                "description": description,
                "rule_id": rule_id,
                "cwe_id": cwe_id,
                "cve_id": None,
                "file_path": file_path,
                "line_number": line_number,
                "url": None,
                "http_method": None,
                "parameter": None,
                "package_name": None,
                "package_version": None,
                "fixed_version": None,
                "cvss_score": None,
                "remediation": remediation,
                "references": [],
            })
        except Exception as e:
            logger.warning("SonarQube finding 파싱 실패, 건너뜀: %s", e)
            continue

    # summary 집계
    summary = _make_summary(findings)

    return {
        "tool": "sonarqube",
        "category": "SAST",
        "scanned_at": scanned_at,
        "target": raw.get("paging", {}).get("total", None) and None,
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
