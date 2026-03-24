"""Grype JSON 출력을 공통 스키마로 정규화합니다."""

from datetime import datetime, timezone

_SEV_MAP = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Negligible": "INFO",
}


class GrypeParser:
    def parse(self, raw):
        matches = raw.get("matches", [])
        findings = []
        for m in matches:
            vuln = m.get("vulnerability", {})
            artifact = m.get("artifact", {})
            sev = _SEV_MAP.get(vuln.get("severity", ""), "MEDIUM")
            findings.append({
                "id": vuln.get("id", ""),
                "tool": "grype",
                "category": "IMAGE",
                "severity": sev,
                "title": f"{artifact.get('name', '')}:{artifact.get('version', '')} - {vuln.get('id', '')}",
                "description": vuln.get("description", "") or vuln.get("id", ""),
                "rule_id": vuln.get("id", ""),
                "cwe_id": None,
                "cve_id": vuln.get("id") if vuln.get("id", "").startswith("CVE") else None,
                "file_path": artifact.get("locations", [{}])[0].get("path") if artifact.get("locations") else None,
                "line_number": None,
                "url": None,
                "package_name": artifact.get("name"),
                "package_version": artifact.get("version"),
                "fixed_version": ",".join(vuln.get("fix", {}).get("versions", [])) if vuln.get("fix", {}).get("versions") else None,
                "cvss_score": None,
                "remediation": None,
                "references": [u for u in vuln.get("urls", []) if isinstance(u, str)] if vuln.get("urls") else [],
            })

        summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            key = f["severity"].lower()
            if key in summary:
                summary[key] += 1

        return {
            "tool": "grype",
            "category": "IMAGE",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "summary": summary,
        }
