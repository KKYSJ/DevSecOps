"""
OWASP Dependency-Check JSON 출력을 공통 finding 포맷으로 파싱합니다.
SCA 카테고리: dependency.vulnerabilities 각 항목이 하나의 finding입니다.
심각도 우선순위: CVSSv3 baseSeverity > CVSSv2 severity > severity 필드
MODERATE → MEDIUM 으로 정규화합니다.
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "NONE": "INFO",
}


def _normalize_severity(vuln: dict) -> str:
    """Dependency-Check 취약점에서 심각도를 추출합니다.
    우선순위: CVSSv3 baseSeverity > CVSSv2 severity > severity 필드
    """
    # CVSSv3 baseSeverity 우선
    cvssv3 = vuln.get("cvssv3") or {}
    base_severity_v3 = cvssv3.get("baseSeverity")
    if base_severity_v3:
        normalized = _SEVERITY_MAP.get(base_severity_v3.upper())
        if normalized:
            return normalized

    # CVSSv2 severity
    cvssv2 = vuln.get("cvssv2") or {}
    severity_v2 = cvssv2.get("severity")
    if severity_v2:
        normalized = _SEVERITY_MAP.get(severity_v2.upper())
        if normalized:
            return normalized

    # severity 필드 직접 사용
    severity = vuln.get("severity") or ""
    return _SEVERITY_MAP.get(severity.upper(), "MEDIUM")


def _make_id(tool: str, vuln_name: str, pkg_name: str) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{vuln_name}:{pkg_name}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_cvss_score(vuln: dict) -> float | None:
    """CVSSv3 점수를 우선 추출하고, 없으면 CVSSv2 점수를 반환합니다."""
    cvssv3 = vuln.get("cvssv3") or {}
    score = cvssv3.get("baseScore")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass

    cvssv2 = vuln.get("cvssv2") or {}
    score = cvssv2.get("score")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass

    return None


def _extract_pkg_info(dependency: dict) -> tuple[str, str]:
    """의존성 정보에서 패키지명과 버전을 추출합니다."""
    # fileName을 패키지명 기본값으로 사용
    pkg_name = dependency.get("fileName") or dependency.get("name") or ""

    # packages 배열에서 purl 파싱
    packages = dependency.get("packages") or []
    for pkg in packages:
        purl = pkg.get("id") or ""
        if purl.startswith("pkg:"):
            # purl 형식: pkg:ecosystem/name@version
            try:
                rest = purl.split("/", 1)
                if len(rest) > 1:
                    name_ver = rest[1]
                    if "@" in name_ver:
                        name, version = name_ver.rsplit("@", 1)
                        # 버전에서 쿼리 파라미터 제거
                        version = version.split("?")[0].split("#")[0]
                        return name.strip(), version.strip()
                    return name_ver.strip(), ""
            except Exception:
                pass

    # 버전 정보는 fileName에서 추출 시도 (예: requests-2.27.1.jar)
    version = ""
    if pkg_name:
        # "-숫자" 패턴으로 버전 분리 시도
        import re
        match = re.search(r"-(\d+[\.\d]*)(?:\.jar|\.zip|\.tar\.gz)?$", pkg_name)
        if match:
            version = match.group(1)
            pkg_name = pkg_name[:match.start()]

    return pkg_name, version


def parse(raw: dict) -> dict:
    """Dependency-Check JSON 출력을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: dependency-check JSON 출력 dict (dependencies 키 포함)

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    # 스캔 정보 추출
    scan_info = raw.get("scanInfo") or {}
    project_info = raw.get("projectInfo") or {}
    project_name = project_info.get("name") or scan_info.get("engineVersion")

    dependencies = raw.get("dependencies") or []

    for dependency in dependencies:
        # 취약점이 없는 의존성은 건너뜀
        vulnerabilities = dependency.get("vulnerabilities") or []
        if not vulnerabilities:
            continue

        # suppress 처리된 취약점 목록
        suppressed = {
            v.get("name", ""): True
            for v in (dependency.get("suppressedVulnerabilities") or [])
        }

        pkg_name, pkg_version = _extract_pkg_info(dependency)

        for vuln in vulnerabilities:
            try:
                vuln_name = vuln.get("name") or ""  # CVE ID 또는 취약점명

                # suppress된 취약점 제외
                if vuln_name in suppressed:
                    continue

                severity = _normalize_severity(vuln)
                cvss_score = _extract_cvss_score(vuln)

                # finding ID 생성
                finding_id = _make_id("depcheck", vuln_name, pkg_name)

                title = vuln.get("description", "")[:120] if vuln.get("description") else vuln_name
                description = vuln.get("description") or ""

                # CWE 추출
                cwes = vuln.get("cwes") or []
                cwe_id = None
                if cwes:
                    cwe_raw = cwes[0]
                    if isinstance(cwe_raw, str):
                        cwe_id = cwe_raw if cwe_raw.upper().startswith("CWE-") else f"CWE-{cwe_raw}"
                    elif isinstance(cwe_raw, int):
                        cwe_id = f"CWE-{cwe_raw}"

                # CVE ID
                cve_id = vuln_name if vuln_name.startswith("CVE-") else None

                # 참고 링크
                references = []
                for ref in (vuln.get("references") or []):
                    url = ref.get("url") if isinstance(ref, dict) else str(ref)
                    if url:
                        references.append(url)

                # 수정 방법 (버전 업그레이드 권고)
                remediation = None
                if pkg_version:
                    remediation = f"{pkg_name} {pkg_version}에서 발견된 취약점입니다. 최신 버전으로 업그레이드하세요."

                # vulnerable software에서 fixed version 추출 시도
                fixed_version = None
                vuln_software = vuln.get("vulnerableSoftware") or []
                for sw in vuln_software:
                    ver_end_exc = sw.get("versionEndExcluding")
                    if ver_end_exc:
                        fixed_version = ver_end_exc
                        break

                findings.append({
                    "id": finding_id,
                    "tool": "depcheck",
                    "category": "SCA",
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "rule_id": vuln_name,
                    "cwe_id": cwe_id,
                    "cve_id": cve_id,
                    "file_path": dependency.get("filePath") or dependency.get("fileName") or None,
                    "line_number": None,
                    "url": None,
                    "http_method": None,
                    "parameter": None,
                    "package_name": pkg_name if pkg_name else None,
                    "package_version": pkg_version if pkg_version else None,
                    "fixed_version": fixed_version,
                    "cvss_score": cvss_score,
                    "remediation": remediation,
                    "references": references,
                })
            except Exception as e:
                logger.warning("Dependency-Check vulnerability 파싱 실패, 건너뜀: %s", e)
                continue

    summary = _make_summary(findings)

    return {
        "tool": "depcheck",
        "category": "SCA",
        "scanned_at": scanned_at,
        "target": project_name,
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
