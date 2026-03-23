"""Normalize nuclei JSON export into the common finding schema."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "unknown": "INFO",
}


def _normalize_severity(raw: Any) -> str:
    if not raw:
        return "MEDIUM"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "MEDIUM")


def _make_finding_id(template_id: str, matched_at: str, matcher_name: str) -> str:
    raw = f"nuclei:{template_id}:{matched_at}:{matcher_name}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _first_value(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]).strip() if value else None
    if value:
        return str(value).strip()
    return None


def _parse_record(record: dict[str, Any]) -> dict[str, Any]:
    info = record.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    template_id = str(record.get("template-id") or record.get("template") or "unknown")
    matcher_name = str(record.get("matcher-name") or "")
    matched_at = str(record.get("matched-at") or record.get("host") or record.get("url") or "")
    severity = _normalize_severity(info.get("severity") or record.get("severity"))
    title = str(info.get("name") or template_id)
    description = str(info.get("description") or title)
    cve_id = _first_value(classification.get("cve-id"))
    cwe_id = _first_value(classification.get("cwe-id"))
    references = info.get("reference") or []
    if isinstance(references, str):
        references = [references]

    return {
        "id": _make_finding_id(template_id, matched_at, matcher_name),
        "tool": "nuclei",
        "category": "DAST",
        "severity": severity,
        "title": title[:120],
        "description": description,
        "rule_id": template_id,
        "cwe_id": cwe_id,
        "cve_id": cve_id,
        "file_path": matched_at or None,
        "line_number": None,
        "url": matched_at or None,
        "http_method": str(record.get("type") or "").upper() or None,
        "parameter": matcher_name or None,
        "package_name": None,
        "package_version": None,
        "fixed_version": None,
        "cvss_score": None,
        "remediation": str(info.get("remediation") or "") or None,
        "references": [str(reference) for reference in references if str(reference).strip()],
    }


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = finding["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class NucleiParser:
    """Normalize nuclei JSON output."""

    def parse(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict) and "data" in raw:
            raw = raw["data"]
        records = raw if isinstance(raw, list) else [raw]
        findings = [_parse_record(record) for record in records if isinstance(record, dict)]

        return {
            "tool": "nuclei",
            "category": "DAST",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": findings[0]["url"] if findings else None,
            "findings": findings,
            "summary": _build_summary(findings),
        }
