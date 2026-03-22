"""
OWASP Dependency-Check JSON 출력 파서

Dependency-Check 실행 명령:
    dependency-check.sh --project secureflow --scan . --format JSON --out depcheck-results.json

Dependency-Check JSON 출력 구조:
    {
      "reportSchema": "1.1",
      "projectInfo": {"name": "secureflow", "reportDate": "..."},
      "dependencies": [
        {
          "fileName": "log4j-core-2.14.1.jar",
          "filePath": "/path/to/log4j-core-2.14.1.jar",
          "packages": [
            {"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
          ],
          "vulnerabilities": [
            {
              "source": "NVD",
              "name": "CVE-2021-44228",
              "severity": "CRITICAL",     // CRITICAL | HIGH | MEDIUM | LOW
              "cvssv3": {"baseScore": 10.0, "baseSeverity": "CRITICAL"},
              "cvssv2": {"score": 9.3, "severity": "HIGH"},
              "description": "Apache Log4j2 ...",
              "references": [
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "name": "NVD"}
              ]
            }
          ]
        }
      ]
    }

severity는 CVSSv3 baseSeverity → CVSSv2 severity → name 필드 순서로 우선 사용
"""

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import unquote


_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",   # 일부 버전에서 사용
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
}


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.upper(), "MEDIUM")


def _extract_severity(vuln: dict) -> str:
    """CVSSv3 → CVSSv2 → severity 필드 순서로 심각도 추출"""
    cvssv3 = vuln.get("cvssv3", {})
    if cvssv3.get("baseSeverity"):
        return _normalize_severity(cvssv3["baseSeverity"])

    cvssv2 = vuln.get("cvssv2", {})
    if cvssv2.get("severity"):
        return _normalize_severity(cvssv2["severity"])

    return _normalize_severity(vuln.get("severity", "MEDIUM"))


def _extract_cvss_score(vuln: dict) -> float | None:
    cvssv3 = vuln.get("cvssv3", {})
    if cvssv3.get("baseScore") is not None:
        return float(cvssv3["baseScore"])
    cvssv2 = vuln.get("cvssv2", {})
    if cvssv2.get("score") is not None:
        return float(cvssv2["score"])
    return None


def _extract_package_info(dependency: dict) -> tuple[str, str]:
    """
    패키지 이름과 버전 추출
    purl에 namespace가 있으면 보존해서 반환합니다.
    """
    packages = dependency.get("packages", [])
    for package in packages:
        pkg_id = str(package.get("id", "")).strip()
        if not pkg_id.startswith("pkg:"):
            continue

        body = unquote(pkg_id[4:]).split("#", 1)[0]
        purl_type, _, remainder = body.partition("/")
        if not remainder:
            continue

        name_part, _, version_part = remainder.rpartition("@")
        if not name_part:
            name_part = remainder
            version_part = ""

        version_part = version_part.split("?", 1)[0].split("#", 1)[0].strip()
        name_part = name_part.strip()
        if not name_part:
            continue

        if purl_type == "maven" and "/" in name_part:
            namespace, artifact = name_part.rsplit("/", 1)
            package_name = f"{namespace}:{artifact}"
        else:
            package_name = name_part

        return package_name, version_part or "unknown"

    # fallback: fileName에서 추출 (예: "log4j-core-2.14.1.jar")
    file_name: str = dependency.get("fileName", "unknown")
    # 버전 패턴 매칭 (예: -2.14.1.jar)
    match = re.search(r"-(\d[\d.]+\d)\.", file_name)
    if match:
        version = match.group(1)
        name = file_name[: file_name.index(f"-{version}")].strip("-")
        return name, version

    return file_name, "unknown"


def _make_finding_id(pkg_name: str, pkg_version: str, cve_id: str) -> str:
    raw = f"depcheck:{pkg_name}:{pkg_version}:{cve_id}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_vulnerability(dependency: dict, vuln: dict) -> dict:
    cve_id: str = vuln.get("name", "unknown")
    description: str = vuln.get("description", "")
    pkg_name, pkg_version = _extract_package_info(dependency)

    refs = [r.get("url") for r in vuln.get("references", []) if r.get("url")]
    fixed_version = None
    for sw in vuln.get("vulnerableSoftware", []) or []:
        if not isinstance(sw, dict):
            continue
        fixed_version = (
            sw.get("versionEndExcluding")
            or sw.get("versionEndIncluding")
            or sw.get("versionStartIncluding")
        )
        if fixed_version:
            break

    return {
        "id": _make_finding_id(pkg_name, pkg_version, cve_id),
        "tool": "depcheck",
        "category": "SCA",
        "severity": _extract_severity(vuln),
        "title": f"{cve_id} in {pkg_name}",
        "description": description,
        "rule_id": cve_id,
        "cwe_id": None,
        "cve_id": cve_id if cve_id.startswith("CVE-") else None,
        "file_path": dependency.get("filePath") or dependency.get("fileName"),
        "line_number": None,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": pkg_name,
        "package_version": pkg_version,
        "fixed_version": fixed_version,
        "cvss_score": _extract_cvss_score(vuln),
        "remediation": f"Upgrade {pkg_name} to a version without {cve_id}",
        "references": refs,
    }


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class DepcheckParser:
    """OWASP Dependency-Check JSON 출력을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: dependency-check --format JSON 출력 딕셔너리
        Returns:
            공통 스키마 딕셔너리
        """
        dependencies: list[dict] = raw.get("dependencies", [])

        findings = []
        for dep in dependencies:
            for vuln in dep.get("vulnerabilities", []):
                findings.append(_parse_vulnerability(dep, vuln))

        return {
            "tool": "depcheck",
            "category": "SCA",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": raw.get("projectInfo", {}).get("name"),
            "findings": findings,
            "summary": _build_summary(findings),
        }
