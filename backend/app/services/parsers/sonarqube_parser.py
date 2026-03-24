"""Parser for SonarQube issues API results."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any


_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "INFO",
}

_RULE_CWE_MAP = {
    "S2068": "CWE-798",
    "S2076": "CWE-78",
    "S2083": "CWE-22",
    "S3649": "CWE-89",
    "S5131": "CWE-79",
    "S5135": "CWE-502",
    "S5144": "CWE-918",
    "S5334": "CWE-95",
}

_TAG_CWE_MAP = {
    "sql": "CWE-89",
}

_MESSAGE_CWE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"hard-?coded (credential|password)", re.IGNORECASE), "CWE-798"),
    (re.compile(r"sql quer(y|ies).*user-controlled data", re.IGNORECASE), "CWE-89"),
    (re.compile(r"os command.*user-controlled data", re.IGNORECASE), "CWE-78"),
    (re.compile(r"construct the path from user-controlled data", re.IGNORECASE), "CWE-22"),
    (re.compile(r"construct the url from user-controlled data", re.IGNORECASE), "CWE-918"),
    (re.compile(r"deserialize user-controlled data", re.IGNORECASE), "CWE-502"),
    (re.compile(r"reflect user-controlled data", re.IGNORECASE), "CWE-79"),
    (re.compile(r"dynamically execute code influenced by user-controlled data", re.IGNORECASE), "CWE-95"),
]


def _normalize_severity(sonar_severity: str) -> str:
    return _SEVERITY_MAP.get((sonar_severity or "").upper(), "MEDIUM")


def _extract_file_path(component: str) -> str | None:
    if not component:
        return None
    parts = component.split(":", 1)
    return parts[1] if len(parts) == 2 else component


def _make_finding_id(issue_key: str) -> str:
    raw = f"sonarqube:{issue_key}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_cwe_from_tags(*tag_groups: Any) -> str | None:
    for tag_group in tag_groups:
        if not isinstance(tag_group, list):
            continue
        for raw_tag in tag_group:
            tag = str(raw_tag or "").strip().lower()
            match = re.search(r"cwe[:_-]?(\d+)", tag)
            if match:
                return f"CWE-{match.group(1)}"
            if tag in _TAG_CWE_MAP:
                return _TAG_CWE_MAP[tag]
    return None


def _extract_cwe_from_rule(rule: str) -> str | None:
    if not rule:
        return None
    suffix = rule.split(":")[-1].strip().upper()
    return _RULE_CWE_MAP.get(suffix)


def _extract_cwe_from_message(message: str) -> str | None:
    for pattern, cwe_id in _MESSAGE_CWE_PATTERNS:
        if pattern.search(message or ""):
            return cwe_id
    return None


def _extract_cwe(issue: dict[str, Any]) -> str | None:
    return (
        _extract_cwe_from_tags(issue.get("tags"), issue.get("internalTags"))
        or _extract_cwe_from_rule(str(issue.get("rule", "")))
        or _extract_cwe_from_message(str(issue.get("message", "")))
    )


def _parse_issue(issue: dict[str, Any]) -> dict[str, Any]:
    issue_key = str(issue.get("key", "unknown"))
    rule = str(issue.get("rule", "unknown"))
    severity_raw = str(issue.get("severity", "MAJOR"))
    component = str(issue.get("component", ""))
    line = issue.get("line") or issue.get("textRange", {}).get("startLine")
    message = str(issue.get("message", rule))
    issue_type = str(issue.get("type", "VULNERABILITY"))
    effort = issue.get("effort") or issue.get("debt")

    try:
        line_number = int(line) if line is not None else None
    except (TypeError, ValueError):
        line_number = None

    file_path = _extract_file_path(component)

    remediation = None
    if effort:
        remediation = f"Estimated remediation effort: {effort}"

    return {
        "id": _make_finding_id(issue_key),
        "tool": "sonarqube",
        "category": "SAST",
        "severity": _normalize_severity(severity_raw),
        "title": message[:120] if message else rule,
        "description": f"[{issue_type}] {message}",
        "rule_id": rule,
        "cwe_id": _extract_cwe(issue),
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
        "references": [f"https://rules.sonarsource.com/{rule.replace(':', '/')}"] if rule else [],
    }


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = str(finding["severity"]).lower()
        if key in summary:
            summary[key] += 1
    return summary


class SonarqubeParser:
    """Parse SonarQube /api/issues/search payloads into the common schema."""

    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        issues = raw.get("issues", [])
        vuln_issues = [issue for issue in issues if issue.get("type") in ("VULNERABILITY", None)]
        findings = [_parse_issue(issue) for issue in vuln_issues]

        return {
            "tool": "sonarqube",
            "category": "SAST",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
