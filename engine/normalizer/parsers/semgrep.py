"""
Semgrep --json 출력을 공통 finding 포맷으로 파싱합니다.
심각도 매핑: CRITICAL→CRITICAL, ERROR→HIGH, WARNING→MEDIUM, INFO→LOW
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "INFO": "LOW",
    "LOW": "LOW",
    "EXPERIMENT": "LOW",
    "INVENTORY": "LOW",
}


def _normalize_severity(raw: str) -> str:
    """Semgrep 심각도를 공통 포맷으로 변환합니다."""
    return _SEVERITY_MAP.get((raw or "").upper(), "MEDIUM")


def _make_id(tool: str, rule_id: str, file_path: str, line: int | None) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{rule_id}:{file_path}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_cwe(metadata: dict) -> str | None:
    """메타데이터에서 CWE ID를 추출합니다."""
    cwe = metadata.get("cwe") or metadata.get("cwe_id")
    if not cwe:
        return None

    # 리스트인 경우 첫 번째 값 사용
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None

    if not cwe:
        return None

    cwe_str = str(cwe)
    # "CWE-89" 형식이면 그대로 반환
    if cwe_str.upper().startswith("CWE-"):
        return cwe_str.upper()

    # 숫자만 있으면 "CWE-N" 형식으로 변환
    if cwe_str.isdigit():
        return f"CWE-{cwe_str}"

    return cwe_str


def _extract_cve(metadata: dict) -> str | None:
    """메타데이터에서 CVE ID를 추출합니다."""
    cve = metadata.get("cve") or metadata.get("cve_id")
    if isinstance(cve, list):
        cve = cve[0] if cve else None
    return str(cve) if cve else None


def _extract_references(metadata: dict, extra: dict) -> list:
    """참고 링크를 추출합니다."""
    refs = []
    # metadata의 references
    meta_refs = metadata.get("references", []) or []
    if isinstance(meta_refs, list):
        refs.extend([r for r in meta_refs if isinstance(r, str)])

    # extra의 references
    extra_refs = extra.get("references", []) or []
    if isinstance(extra_refs, list):
        refs.extend([r for r in extra_refs if isinstance(r, str)])

    return list(dict.fromkeys(refs))  # 중복 제거, 순서 유지


def parse(raw: dict) -> dict:
    """Semgrep JSON 출력을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: semgrep --json 출력 dict (results 키 포함)

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    results = raw.get("results", [])

    for result in results:
        try:
            # ignore 처리된 항목 제외
            if result.get("extra", {}).get("is_ignored", False):
                continue

            check_id = result.get("check_id", "")
            path = result.get("path", "")
            start = result.get("start", {})
            end = result.get("end", {})
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}

            # 라인 번호
            line_number = start.get("line")
            if line_number is not None:
                try:
                    line_number = int(line_number)
                except (ValueError, TypeError):
                    line_number = None

            # 심각도
            raw_severity = (
                extra.get("severity")
                or metadata.get("severity")
                or result.get("severity")
                or "WARNING"
            )
            severity = _normalize_severity(raw_severity)

            # finding ID 생성
            finding_id = _make_id("semgrep", check_id, path, line_number)

            # 제목 (message 요약)
            message = extra.get("message", "") or ""
            title = metadata.get("shortDescription") or (
                message[:120] + "..." if len(message) > 120 else message
            ) or check_id

            # CWE/CVE 추출
            cwe_id = _extract_cwe(metadata)
            cve_id = _extract_cve(metadata)

            # 수정 방법
            remediation = metadata.get("fix") or metadata.get("message") or None

            # 참고 링크
            references = _extract_references(metadata, extra)

            # CVSS 점수
            cvss_score = None
            cvss_raw = metadata.get("cvss")
            if cvss_raw is not None:
                try:
                    cvss_score = float(cvss_raw)
                except (ValueError, TypeError):
                    pass

            findings.append({
                "id": finding_id,
                "tool": "semgrep",
                "category": "SAST",
                "severity": severity,
                "title": title,
                "description": message,
                "rule_id": check_id,
                "cwe_id": cwe_id,
                "cve_id": cve_id,
                "file_path": path if path else None,
                "line_number": line_number,
                "url": None,
                "http_method": None,
                "parameter": None,
                "package_name": None,
                "package_version": None,
                "fixed_version": None,
                "cvss_score": cvss_score,
                "remediation": remediation,
                "references": references,
            })
        except Exception as e:
            logger.warning("Semgrep finding 파싱 실패, 건너뜀: %s", e)
            continue

    summary = _make_summary(findings)

    return {
        "tool": "semgrep",
        "category": "SAST",
        "scanned_at": scanned_at,
        "target": raw.get("paths", {}).get("scanned", [None])[0] if raw.get("paths", {}).get("scanned") else None,
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
