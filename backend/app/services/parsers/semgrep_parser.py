"""
Semgrep JSON 출력 파서

Semgrep 실행 명령:
    semgrep --config auto --json -o semgrep-results.json ./

Semgrep JSON 출력 구조:
    {
      "results": [
        {
          "check_id": "python.lang.security.audit.insecure-os-system",
          "path": "backend/app/main.py",
          "start": {"line": 42, "col": 5},
          "end":   {"line": 42, "col": 30},
          "extra": {
            "message": "Use of os.system() detected",
            "severity": "WARNING",   // ERROR | WARNING | INFO
            "metadata": {
              "cwe": ["CWE-78: Improper Neutralization..."],
              "owasp": ["A03:2021 - Injection"]
            },
            "fix": "Use subprocess.run() instead"
          }
        }
      ],
      "errors": []
    }

Semgrep severity → 공통 severity 매핑:
    ERROR   → HIGH
    WARNING → MEDIUM
    INFO    → LOW
"""

import hashlib
from datetime import datetime, timezone
from typing import Any


_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def _normalize_severity(semgrep_severity: str) -> str:
    return _SEVERITY_MAP.get(semgrep_severity.upper(), "MEDIUM")


def _extract_cwe(metadata: dict) -> str | None:
    """metadata.cwe 리스트에서 첫 번째 CWE ID만 추출 (예: 'CWE-78')"""
    cwe_list = metadata.get("cwe", [])
    if not cwe_list:
        return None
    raw = cwe_list[0]
    # "CWE-78: Improper ..." 형태에서 "CWE-78"만 추출
    return raw.split(":")[0].strip()


def _make_finding_id(check_id: str, path: str, line: int) -> str:
    raw = f"semgrep:{check_id}:{path}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_finding(result: dict) -> dict:
    check_id: str = result.get("check_id", "unknown")
    path: str = result.get("path", "")
    start: dict = result.get("start", {})
    line: int = start.get("line")

    extra: dict = result.get("extra", {})
    message: str = extra.get("message", check_id)
    severity_raw: str = extra.get("severity", "WARNING")
    metadata: dict = extra.get("metadata", {})
    fix: str | None = extra.get("fix")

    # references: owasp / references 필드
    refs = []
    for owasp in metadata.get("owasp", []):
        refs.append(owasp)
    for ref in metadata.get("references", []):
        refs.append(ref)

    return {
        "id": _make_finding_id(check_id, path, line or 0),
        "tool": "semgrep",
        "category": "SAST",
        "severity": _normalize_severity(severity_raw),
        "title": check_id.split(".")[-1].replace("-", " ").replace("_", " ").title(),
        "description": message,
        "rule_id": check_id,
        "cwe_id": _extract_cwe(metadata),
        "cve_id": None,
        "file_path": path or None,
        "line_number": line,
        "url": None,
        "http_method": None,
        "parameter": None,
        "package_name": None,
        "package_version": None,
        "fixed_version": None,
        "cvss_score": None,
        "remediation": fix,
        "references": refs,
    }


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class SemgrepParser:
    """Semgrep JSON 출력을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: semgrep --json 출력 딕셔너리
        Returns:
            공통 스키마 딕셔너리
        """
        results: list[dict] = raw.get("results", [])
        findings = [_parse_finding(r) for r in results]

        return {
            "tool": "semgrep",
            "category": "SAST",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
