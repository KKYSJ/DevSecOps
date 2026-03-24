"""Normalize SonarQube issues API responses into the common finding schema."""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "INFO",
}

_VALID_STATUSES = {"OPEN", "REOPENED", "CONFIRMED"}

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


def _normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get((raw or "").upper(), "MEDIUM")


def _make_id(tool: str, rule_id: str, file_path: str, line: int | None) -> str:
    raw = f"{tool}:{rule_id}:{file_path}:{line}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_file_path(issue: dict[str, Any]) -> str | None:
    component_key = str(issue.get("component", ""))

    components = issue.get("_components", [])
    for component in components:
        if component.get("key") == component_key:
            path = component.get("path")
            if path:
                return path

    if ":" in component_key:
        return component_key.split(":", 1)[1]

    return component_key or None


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


def _extract_cwe_from_rule(rule_id: str) -> str | None:
    suffix = rule_id.split(":")[-1].strip().upper()
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


def parse(raw: dict[str, Any]) -> dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []
    issues = raw.get("issues", [])
    components = raw.get("components", [])

    for issue in issues:
        try:
            status = str(issue.get("status", "OPEN")).upper()
            if status not in _VALID_STATUSES:
                continue

            issue["_components"] = components

            rule_id = str(issue.get("rule", ""))
            severity = _normalize_severity(str(issue.get("severity", "MAJOR")))
            file_path = _extract_file_path(issue)

            line_number = issue.get("line") or issue.get("textRange", {}).get("startLine")
            if line_number is not None:
                try:
                    line_number = int(line_number)
                except (TypeError, ValueError):
                    line_number = None

            finding_id = _make_id("sonarqube", rule_id, file_path or "", line_number)
            message = str(issue.get("message", rule_id) or rule_id)
            effort = issue.get("effort") or issue.get("debt")

            remediation = None
            if effort:
                remediation = f"Estimated remediation effort: {effort}"

            findings.append(
                {
                    "id": finding_id,
                    "tool": "sonarqube",
                    "category": "SAST",
                    "severity": severity,
                    "title": message,
                    "description": message,
                    "rule_id": rule_id,
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
                    "references": [],
                }
            )
        except Exception as exc:  # pragma: no cover - defensive parser hardening
            logger.warning("Failed to parse SonarQube finding, skipping: %s", exc)
            continue

    return {
        "tool": "sonarqube",
        "category": "SAST",
        "scanned_at": scanned_at,
        "target": None,
        "findings": findings,
        "summary": _make_summary(findings),
    }


def _make_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        counts[severity] = counts.get(severity, 0) + 1

    return {
        "total": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
    }
