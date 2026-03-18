"""
Trivy JSON 출력을 공통 finding 포맷으로 파싱합니다.
SCA 카테고리: Results[].Vulnerabilities 각 항목이 하나의 finding입니다.
심각도: CRITICAL→CRITICAL, HIGH→HIGH, MEDIUM→MEDIUM, LOW→LOW
심각도가 null인 경우 CVSS V3Score 기준으로 결정합니다.
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
    "UNKNOWN": "LOW",
    "NONE": "INFO",
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _normalize_severity(raw: str, cvss_score: float | None) -> str:
    """Trivy 심각도를 공통 포맷으로 변환합니다.
    severity가 없거나 UNKNOWN이면 CVSS 점수로 결정합니다.
    """
    if raw:
        upper = raw.upper()
        if upper in _SEVERITY_MAP and upper not in ("UNKNOWN", "NONE"):
            return _SEVERITY_MAP[upper]

    # CVSS 점수 기반 fallback
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    return _SEVERITY_MAP.get((raw or "").upper(), "LOW")


def _make_id(tool: str, vuln_id: str, pkg_name: str, pkg_version: str) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{vuln_id}:{pkg_name}:{pkg_version}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_cvss_score(vuln: dict) -> float | None:
    """취약점에서 CVSS V3 점수를 추출합니다."""
    cvss = vuln.get("CVSS") or {}

    # NVD V3 점수 우선
    nvd = cvss.get("nvd") or {}
    v3_score = nvd.get("V3Score")
    if v3_score is not None:
        try:
            return float(v3_score)
        except (ValueError, TypeError):
            pass

    # Redhat V3 점수
    redhat = cvss.get("redhat") or {}
    v3_score = redhat.get("V3Score")
    if v3_score is not None:
        try:
            return float(v3_score)
        except (ValueError, TypeError):
            pass

    # 다른 소스에서 V3Score 검색
    for source_data in cvss.values():
        if isinstance(source_data, dict):
            v3 = source_data.get("V3Score")
            if v3 is not None:
                try:
                    return float(v3)
                except (ValueError, TypeError):
                    pass

    return None


def parse(raw: dict) -> dict:
    """Trivy JSON 출력을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: Trivy JSON 출력 dict (Results 키 포함)

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    artifact_name = raw.get("ArtifactName") or raw.get("artifactName")
    results = raw.get("Results") or raw.get("results") or []

    for result in results:
        target = result.get("Target") or result.get("target", "")
        vulnerabilities = result.get("Vulnerabilities") or result.get("vulnerabilities") or []

        for vuln in vulnerabilities:
            try:
                vuln_id = vuln.get("VulnerabilityID") or vuln.get("vulnerabilityID", "")
                pkg_name = vuln.get("PkgName") or vuln.get("pkgName", "")
                installed_version = vuln.get("InstalledVersion") or vuln.get("installedVersion", "")
                fixed_version = vuln.get("FixedVersion") or vuln.get("fixedVersion") or None
                title = vuln.get("Title") or vuln.get("title") or vuln_id
                description = vuln.get("Description") or vuln.get("description") or ""
                raw_severity = vuln.get("Severity") or vuln.get("severity") or ""
                references = vuln.get("References") or vuln.get("references") or []

                # CVSS 점수 추출
                cvss_score = _extract_cvss_score(vuln)

                # 심각도 정규화
                severity = _normalize_severity(raw_severity, cvss_score)

                # finding ID 생성
                finding_id = _make_id("trivy", vuln_id, pkg_name, installed_version)

                # CWE 추출
                cwe_ids = vuln.get("CweIDs") or vuln.get("cweIDs") or []
                cwe_id = cwe_ids[0] if cwe_ids else None

                # 참고 링크 필터링
                ref_list = [r for r in (references or []) if isinstance(r, str)]

                # 수정 방법
                remediation = None
                if fixed_version:
                    remediation = f"{pkg_name}을(를) {fixed_version} 이상으로 업그레이드하세요."

                findings.append({
                    "id": finding_id,
                    "tool": "trivy",
                    "category": "SCA",
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "rule_id": vuln_id,
                    "cwe_id": cwe_id,
                    "cve_id": vuln_id if vuln_id.startswith("CVE-") else None,
                    "file_path": target if target else None,
                    "line_number": None,
                    "url": None,
                    "http_method": None,
                    "parameter": None,
                    "package_name": pkg_name if pkg_name else None,
                    "package_version": installed_version if installed_version else None,
                    "fixed_version": fixed_version,
                    "cvss_score": cvss_score,
                    "remediation": remediation,
                    "references": ref_list,
                })
            except Exception as e:
                logger.warning("Trivy vulnerability 파싱 실패, 건너뜀: %s", e)
                continue

    summary = _make_summary(findings)

    return {
        "tool": "trivy",
        "category": "SCA",
        "scanned_at": scanned_at,
        "target": artifact_name,
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
