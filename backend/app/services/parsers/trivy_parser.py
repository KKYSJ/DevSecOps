"""
Trivy JSON 출력 파서

Trivy 실행 명령:
    trivy image --format json --output trivy-results.json backend:latest
    trivy fs --format json --output trivy-results.json .

Trivy JSON 출력 구조 (SchemaVersion 2):
    {
      "SchemaVersion": 2,
      "ArtifactName": "backend:latest",
      "ArtifactType": "container_image",
      "Results": [
        {
          "Target": "requirements.txt",
          "Class": "lang-pkgs",
          "Type": "pip",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2023-1234",
              "PkgName": "requests",
              "InstalledVersion": "2.27.1",
              "FixedVersion": "2.31.0",
              "Severity": "HIGH",
              "Title": "...",
              "Description": "...",
              "CVSS": {"nvd": {"V3Score": 7.5}},
              "References": ["https://..."]
            }
          ]
        }
      ]
    }

Trivy severity → 공통 severity 매핑:
    CRITICAL → CRITICAL
    HIGH     → HIGH
    MEDIUM   → MEDIUM
    LOW      → LOW
    UNKNOWN  → INFO
"""

import hashlib
from datetime import datetime, timezone


_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
}


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.upper(), "MEDIUM")


def _extract_cvss_score(cvss: dict) -> float | None:
    """CVSS 딕셔너리에서 V3Score 우선, 없으면 V2Score"""
    if not cvss:
        return None
    for source in ("nvd", "redhat"):
        source_data = cvss.get(source, {})
        if source_data.get("V3Score") is not None:
            return float(source_data["V3Score"])
        if source_data.get("V2Score") is not None:
            return float(source_data["V2Score"])
    # 임의 소스에서 첫 번째 점수 추출
    for source_data in cvss.values():
        if isinstance(source_data, dict):
            if source_data.get("V3Score") is not None:
                return float(source_data["V3Score"])
    return None


def _make_finding_id(cve_id: str, pkg_name: str, pkg_version: str) -> str:
    raw = f"trivy:{cve_id}:{pkg_name}:{pkg_version}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_vulnerability(vuln: dict, target: str) -> dict:
    cve_id: str = vuln.get("VulnerabilityID", "unknown")
    pkg_name: str = vuln.get("PkgName", "unknown")
    installed_version: str = vuln.get("InstalledVersion", "unknown")
    fixed_version: str | None = vuln.get("FixedVersion") or None
    severity_raw: str = vuln.get("Severity", "UNKNOWN")
    title: str = vuln.get("Title", cve_id)
    description: str = vuln.get("Description", "")
    cvss: dict = vuln.get("CVSS", {})
    references: list = vuln.get("References", [])

    return {
        "id": _make_finding_id(cve_id, pkg_name, installed_version),
        "tool": "trivy",
        "category": "SCA",
        "severity": _normalize_severity(severity_raw),
        "title": title[:120] if title else cve_id,
        "description": description,
        "rule_id": cve_id,
        "cwe_id": None,
        "cve_id": cve_id if cve_id.startswith("CVE-") else None,
        "file_path": target or None,
        "line_number": None,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": pkg_name,
        "package_version": installed_version,
        "fixed_version": fixed_version,
        "cvss_score": _extract_cvss_score(cvss),
        "remediation": f"Upgrade {pkg_name} to {fixed_version}" if fixed_version else None,
        "references": references,
    }


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class TrivyParser:
    """Trivy JSON 출력을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: trivy --format json 출력 딕셔너리
        Returns:
            공통 스키마 딕셔너리
        """
        artifact_name: str = raw.get("ArtifactName", "")
        results: list[dict] = raw.get("Results", [])
        if results is None:
            results = []

        findings = []
        for result in results:
            target: str = result.get("Target", artifact_name)
            vulnerabilities: list[dict] = result.get("Vulnerabilities", []) or []
            for vuln in vulnerabilities:
                findings.append(_parse_vulnerability(vuln, target))

        return {
            "tool": "trivy",
            "category": "SCA",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": artifact_name or None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
