"""
SonarQube API 결과 파서

SonarQube API 호출:
    GET /api/issues/search?componentKeys={projectKey}&types=VULNERABILITY&resolved=false

SonarQube API 응답 구조:
    {
      "total": 10,
      "issues": [
        {
          "key": "AXcdk3L4HnGe0ub2",
          "rule": "python:S2076",
          "severity": "CRITICAL",   // BLOCKER | CRITICAL | MAJOR | MINOR | INFO
          "component": "secureflow:backend/app/main.py",
          "line": 42,
          "message": "Make sure that using os.system() is safe here.",
          "type": "VULNERABILITY",  // VULNERABILITY | BUG | CODE_SMELL
          "status": "OPEN",
          "tags": ["cwe", "owasp-a3"]
        }
      ]
    }

SonarQube severity → 공통 severity 매핑:
    BLOCKER  → CRITICAL
    CRITICAL → HIGH
    MAJOR    → MEDIUM
    MINOR    → LOW
    INFO     → INFO
"""

import hashlib
from datetime import datetime, timezone


_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "INFO",
}


def _normalize_severity(sonar_severity: str) -> str:
    return _SEVERITY_MAP.get(sonar_severity.upper(), "MEDIUM")


def _extract_file_path(component: str) -> str | None:
    """
    SonarQube component 형태: "projectKey:path/to/file.py"
    ':' 뒤의 경로만 추출
    """
    if not component:
        return None
    parts = component.split(":", 1)
    return parts[1] if len(parts) == 2 else component


def _make_finding_id(issue_key: str) -> str:
    raw = f"sonarqube:{issue_key}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_issue(issue: dict) -> dict:
    issue_key: str = issue.get("key", "unknown")
    rule: str = issue.get("rule", "unknown")
    severity_raw: str = issue.get("severity", "MAJOR")
    component: str = issue.get("component", "")
    line: int | None = issue.get("line")
    message: str = issue.get("message", rule)
    issue_type: str = issue.get("type", "VULNERABILITY")

    # VULNERABILITY 타입만 보안 이슈 - BUG/CODE_SMELL은 참고용
    file_path = _extract_file_path(component)

    return {
        "id": _make_finding_id(issue_key),
        "tool": "sonarqube",
        "category": "SAST",
        "severity": _normalize_severity(severity_raw),
        "title": message[:120] if message else rule,
        "description": f"[{issue_type}] {message}",
        "rule_id": rule,
        "cwe_id": None,   # SonarQube API에 CWE 정보 없음 (rule 문서에는 있음)
        "cve_id": None,
        "file_path": file_path,
        "line_number": line,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": None,
        "package_version": None,
        "fixed_version": None,
        "cvss_score": None,
        "remediation": None,
        "references": [
            f"https://rules.sonarsource.com/{rule.replace(':', '/')}"
        ] if rule else [],
    }


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class SonarqubeParser:
    """SonarQube /api/issues/search 응답을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: SonarQube API /api/issues/search 응답 딕셔너리
        Returns:
            공통 스키마 딕셔너리
        """
        issues: list[dict] = raw.get("issues", [])

        # VULNERABILITY 타입만 보안 이슈로 처리 (BUG/CODE_SMELL 제외)
        vuln_issues = [i for i in issues if i.get("type") in ("VULNERABILITY", None)]
        findings = [_parse_issue(i) for i in vuln_issues]

        return {
            "tool": "sonarqube",
            "category": "SAST",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
