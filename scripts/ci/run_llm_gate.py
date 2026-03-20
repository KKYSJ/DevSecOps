#!/usr/bin/env python3
"""Normalize security tool outputs, compare findings, and produce a stage gate decision."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from backend.app.services.llm.analyzer import run as run_llm_analyzer
from backend.app.services.parsers.checkov_parser import CheckovParser
from backend.app.services.parsers.depcheck_parser import DepcheckParser
from backend.app.services.parsers.nuclei_parser import NucleiParser
from backend.app.services.parsers.semgrep_parser import SemgrepParser
from backend.app.services.parsers.sonarqube_parser import SonarqubeParser
from backend.app.services.parsers.tfsec_parser import TfsecParser
from backend.app.services.parsers.trivy_parser import TrivyParser
from backend.app.services.parsers.zap_parser import ZapParser


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
GATE_PROMPT_FILES = {
    "iac": Path("backend/app/prompts/iac_gate_prompt.txt"),
    "sast": Path("backend/app/prompts/sast_gate_prompt.txt"),
    "sca": Path("backend/app/prompts/sca_gate_prompt.txt"),
    "dast": Path("backend/app/prompts/dast_gate_prompt.txt"),
}
MATCH_PROMPT_FILES = {
    "iac": Path("backend/app/prompts/iac_match_adjudication_prompt.txt"),
    "sast": Path("backend/app/prompts/sast_match_adjudication_prompt.txt"),
    "sca": Path("backend/app/prompts/sca_match_adjudication_prompt.txt"),
    "dast": Path("backend/app/prompts/dast_match_adjudication_prompt.txt"),
}
STAGE_CATEGORY = {
    "iac": "IaC",
    "sast": "SAST",
    "sca": "SCA",
    "dast": "DAST",
}
DEFAULT_THRESHOLDS = {
    "iac": {"critical": 0, "high": 2, "medium_review": 10},
    "sast": {"critical": 0, "high": 3, "medium_review": 15},
    "sca": {"critical": 0, "high": 5, "medium_review": 20},
    "dast": {"critical": 0, "high": 0, "medium_review": 5},
}
SEVERITY_ALIASES = {
    "blocker": "critical",
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "unknown": "medium",
}
MATCH_THRESHOLDS = {
    "iac": 0.76,
    "sast": 0.78,
    "sca": 0.75,
    "dast": 0.80,
}
MAX_LLM_FINDINGS_PER_TOOL = 15
MAX_LLM_MATCH_CANDIDATES = 20
SAST_LLM_CANDIDATE_LINE_DISTANCE = 5
TEXT_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "be",
    "by",
    "detected",
    "disabled",
    "ensure",
    "for",
    "from",
    "here",
    "in",
    "is",
    "it",
    "make",
    "not",
    "of",
    "on",
    "or",
    "safe",
    "that",
    "the",
    "to",
    "use",
    "using",
    "with",
}
TOOL_PARSERS = {
    "checkov": CheckovParser(),
    "tfsec": TfsecParser(),
    "semgrep": SemgrepParser(),
    "sonarqube": SonarqubeParser(),
    "depcheck": DepcheckParser(),
    "trivy": TrivyParser(),
    "zap": ZapParser(),
    "nuclei": NucleiParser(),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=sorted(GATE_PROMPT_FILES))
    parser.add_argument(
        "--tool-input",
        action="append",
        default=[],
        help="Provide tool=input.json pairs, e.g. semgrep=artifacts/semgrep.json",
    )
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load_json(path: Path) -> Any:
    content = path.read_text(encoding="utf-8-sig").strip()
    if not content:
        return {}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        records = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records


def empty_summary() -> dict[str, int]:
    return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def normalize_severity(raw: Any, default: str = "medium") -> str:
    if raw is None:
        return default
    text = str(raw).strip().lower()
    if text.isdigit():
        return {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(text, default)
    return SEVERITY_ALIASES.get(text, default)


def severity_rank(value: Any) -> int:
    return SEVERITY_ORDER.index(normalize_severity(value))


def severity_max(*values: Any) -> str:
    normalized = [normalize_severity(value) for value in values if value is not None]
    if not normalized:
        return "medium"
    return min(normalized, key=severity_rank)


def add_finding(summary: dict[str, int], severity: Any) -> None:
    level = normalize_severity(severity)
    summary["total"] += 1
    summary[level] += 1


def sum_summaries(*summaries: dict[str, int]) -> dict[str, int]:
    combined = empty_summary()
    for summary in summaries:
        for key in combined:
            combined[key] += summary.get(key, 0)
    return combined


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = empty_summary()
    for finding in findings:
        add_finding(summary, finding.get("severity"))
    return summary


def build_empty_normalized(tool: str, stage: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "category": STAGE_CATEGORY[stage],
        "scanned_at": None,
        "target": None,
        "findings": [],
        "summary": empty_summary(),
    }


def normalize_tool_output(tool: str, path: Path, stage: str) -> dict[str, Any]:
    if tool not in TOOL_PARSERS:
        raise ValueError(f"Unsupported tool: {tool}")

    data = load_json(path)
    disabled = isinstance(data, dict) and data.get("tool_disabled", False)
    normalized = build_empty_normalized(tool, stage) if disabled else TOOL_PARSERS[tool].parse(data)
    findings = normalized.get("findings", [])
    summary = summarize_findings(findings)
    normalized["summary"] = summary
    return {
        "tool": tool,
        "path": str(path),
        "summary": summary,
        "executed": not disabled,
        "disabled_reason": data.get("reason") if disabled and isinstance(data, dict) else None,
        "findings": findings,
        "normalized": normalized,
    }


def normalize_path(path: Any) -> str | None:
    if not path:
        return None
    text = str(path).replace("\\", "/").strip().lower()
    return text or None


def normalize_package_name(name: Any) -> str | None:
    if not name:
        return None
    return re.sub(r"[^a-z0-9_.-]+", "", str(name).strip().lower()) or None


def normalize_package_version(version: Any) -> str | None:
    if not version:
        return None
    text = str(version).strip().lower()
    if text.startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    return text or None


def version_aliases(version: Any) -> set[str]:
    aliases: set[str] = set()
    normalized = normalize_package_version(version)
    if normalized:
        aliases.add(normalized)
    if not version:
        return aliases
    for match in re.findall(r"\d+(?:\.\d+){1,}(?:[-._][a-z0-9]+)?", str(version).lower()):
        token = match.lstrip("v")
        if token:
            aliases.add(token)
    return aliases


def versions_overlap(left: Any, right: Any) -> bool:
    left_aliases = version_aliases(left)
    right_aliases = version_aliases(right)
    if not left_aliases or not right_aliases:
        return False
    return bool(left_aliases & right_aliases)


def normalize_identifier(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().lower()
    return text or None


SCA_PACKAGE_NOISE_TOKENS = {
    "apk",
    "archive",
    "composer",
    "deb",
    "gem",
    "github",
    "golang",
    "jar",
    "js",
    "lib",
    "library",
    "maven",
    "npm",
    "nuget",
    "pkg",
    "pypi",
    "py",
    "rpm",
    "tar",
    "war",
    "wheel",
    "zip",
}
SCA_WEAK_PACKAGE_ALIASES = {"api", "app", "cli", "common", "core", "sdk"}


def package_aliases(name: Any) -> set[str]:
    if not name:
        return set()

    raw = str(name).strip().lower()
    if not raw:
        return set()

    canonical = re.sub(r"[^a-z0-9]+", "", raw)
    aliases = {canonical} if canonical else set()

    text = raw
    if text.startswith("pkg:"):
        text = text[4:]
        if "/" in text:
            text = text.split("/", 1)[1]
    text = unquote(text)

    if "@" in text and not text.startswith("@") and re.search(r"@\d", text):
        text = text.rsplit("@", 1)[0]

    parts = []
    for part in re.split(r"[:/@]", text):
        cleaned = re.sub(r"[^a-z0-9]+", "", part)
        if not cleaned or cleaned in SCA_PACKAGE_NOISE_TOKENS:
            continue
        parts.append(cleaned)

    if not parts:
        return aliases

    aliases.add("".join(parts))

    tail = parts[-1]
    if len(tail) >= 5 and tail not in SCA_WEAK_PACKAGE_ALIASES:
        aliases.add(tail)

    if len(parts) >= 2:
        tail_pair = "".join(parts[-2:])
        if len(tail_pair) >= 8:
            aliases.add(tail_pair)

    return {alias for alias in aliases if alias}


def package_match_strength(left_name: Any, right_name: Any) -> tuple[float, str]:
    left_normalized = normalize_package_name(left_name)
    right_normalized = normalize_package_name(right_name)
    if left_normalized and right_normalized and left_normalized == right_normalized:
        return 1.0, "package_name"

    overlap = package_aliases(left_name) & package_aliases(right_name)
    if overlap:
        longest = max(len(alias) for alias in overlap)
        if longest >= 12:
            return 0.92, "package_alias"
        if longest >= 8:
            return 0.84, "package_alias"

    similarity = jaccard_similarity((left_name,), (right_name,))
    if similarity >= 0.72:
        return 0.80, "package_name_similarity"
    if similarity >= 0.50:
        return 0.68, "package_name_similarity"

    return 0.0, "no_package_match"


def shared_vulnerability_identifier(left: dict[str, Any], right: dict[str, Any]) -> tuple[str | None, str | None]:
    left_ids = {
        "cve_id": normalize_identifier(left.get("cve_id")),
        "rule_id": normalize_identifier(left.get("rule_id")),
    }
    right_ids = {
        "cve_id": normalize_identifier(right.get("cve_id")),
        "rule_id": normalize_identifier(right.get("rule_id")),
    }

    for left_key, left_value in left_ids.items():
        if not left_value:
            continue
        for right_key, right_value in right_ids.items():
            if left_value and right_value and left_value == right_value:
                basis = "cve_id" if "cve_id" in {left_key, right_key} else "rule_id"
                return left_value, basis

    return None, None


def normalize_url_path(url: Any) -> str | None:
    if not url:
        return None
    text = str(url).strip()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"https://placeholder{text}")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path.rstrip("/").lower() or "/"


def safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def text_tokens(*values: Any) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        if not value:
            continue
        for token in re.findall(r"[a-z0-9]+", str(value).lower()):
            if len(token) < 3 or token in TEXT_STOP_WORDS:
                continue
            tokens.add(token)
    return tokens


def jaccard_similarity(*value_groups: tuple[Any, ...]) -> float:
    if len(value_groups) != 2:
        return 0.0
    left = text_tokens(*value_groups[0])
    right = text_tokens(*value_groups[1])
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    compact = {
        "tool": finding.get("tool"),
        "severity": normalize_severity(finding.get("severity")),
        "title": finding.get("title"),
        "rule_id": finding.get("rule_id"),
        "file_path": finding.get("file_path"),
        "line_number": finding.get("line_number"),
        "url": finding.get("url"),
        "parameter": finding.get("parameter"),
        "package_name": finding.get("package_name"),
        "package_version": finding.get("package_version"),
        "fixed_version": finding.get("fixed_version"),
        "cve_id": finding.get("cve_id"),
        "cwe_id": finding.get("cwe_id"),
        "cvss_score": finding.get("cvss_score"),
        "description": (finding.get("description") or "")[:240],
    }
    duplicate_count = safe_int(finding.get("duplicate_count")) or 0
    if duplicate_count > 1:
        compact["duplicate_count"] = duplicate_count
        compact["duplicate_rule_ids"] = list(finding.get("duplicate_rule_ids", []))[:5]
    return compact


def sort_findings_for_llm(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            severity_rank(item.get("severity")),
            normalize_identifier(item.get("title")) or "",
            normalize_identifier(item.get("rule_id")) or "",
        ),
    )


def collapse_sast_near_duplicates(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[tuple[str, str, int | None, str, str], list[dict[str, Any]]] = {}

    for finding in findings:
        path = normalize_path(finding.get("file_path")) or ""
        line = safe_int(finding.get("line_number"))
        cwe = normalize_identifier(finding.get("cwe_id")) or ""
        rule = normalize_identifier(finding.get("rule_id")) or ""
        duplicate_key = cwe if cwe else rule
        group_key = (
            normalize_identifier(finding.get("tool")) or "",
            path,
            line,
            duplicate_key,
            "cwe" if cwe else "rule",
        )
        grouped.setdefault(group_key, []).append(finding)

    collapsed: list[dict[str, Any]] = []
    duplicate_count = 0

    for group in grouped.values():
        if len(group) == 1:
            collapsed.append(group[0])
            continue

        duplicate_count += len(group) - 1
        representative = min(
            group,
            key=lambda item: (
                severity_rank(item.get("severity")),
                -(len(item.get("description") or "")),
                normalize_identifier(item.get("title")) or "",
            ),
        )
        merged = dict(representative)
        merged["severity"] = severity_max(*(item.get("severity") for item in group))
        merged["duplicate_count"] = len(group)
        merged["duplicate_rule_ids"] = sorted(
            {
                str(item.get("rule_id")).strip()
                for item in group
                if str(item.get("rule_id", "")).strip()
            }
        )
        merged["duplicate_titles"] = sorted(
            {
                str(item.get("title")).strip()
                for item in group
                if str(item.get("title", "")).strip()
            }
        )[:5]
        merged["source_finding_ids"] = [str(item.get("id")) for item in group if item.get("id")]
        collapsed.append(merged)

    return sort_findings_for_llm(collapsed), duplicate_count


def collapse_sca_duplicates(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}

    for finding in findings:
        package_name = normalize_package_name(finding.get("package_name")) or ""
        package_version = normalize_package_version(finding.get("package_version")) or ""
        cve_id = normalize_identifier(finding.get("cve_id")) or ""
        rule_id = normalize_identifier(finding.get("rule_id")) or ""
        duplicate_key = cve_id if cve_id else rule_id
        group_key = (
            normalize_identifier(finding.get("tool")) or "",
            package_name,
            package_version,
            duplicate_key,
        )
        grouped.setdefault(group_key, []).append(finding)

    collapsed: list[dict[str, Any]] = []
    duplicate_count = 0

    for group in grouped.values():
        if len(group) == 1:
            collapsed.append(group[0])
            continue

        duplicate_count += len(group) - 1
        representative = min(
            group,
            key=lambda item: (
                severity_rank(item.get("severity")),
                -(float(item.get("cvss_score") or 0)),
                -(len(item.get("description") or "")),
                normalize_identifier(item.get("title")) or "",
            ),
        )
        merged = dict(representative)
        merged["severity"] = severity_max(*(item.get("severity") for item in group))
        merged["duplicate_count"] = len(group)
        merged["duplicate_rule_ids"] = sorted(
            {
                str(item.get("rule_id")).strip()
                for item in group
                if str(item.get("rule_id", "")).strip()
            }
        )
        merged["duplicate_titles"] = sorted(
            {
                str(item.get("title")).strip()
                for item in group
                if str(item.get("title", "")).strip()
            }
        )[:5]
        merged["source_finding_ids"] = [str(item.get("id")) for item in group if item.get("id")]
        collapsed.append(merged)

    return sort_findings_for_llm(collapsed), duplicate_count


def merge_matched_finding(
    stage: str,
    left: dict[str, Any],
    right: dict[str, Any],
    score: float,
    basis: str,
) -> dict[str, Any]:
    merged = dict(left)
    merged["category"] = STAGE_CATEGORY[stage]
    merged["severity"] = severity_max(left.get("severity"), right.get("severity"))
    merged["tools"] = [left.get("tool"), right.get("tool")]
    merged["matched_with"] = right.get("tool")
    merged["match_score"] = round(score, 3)
    merged["match_basis"] = basis
    merged["paired_finding"] = compact_finding(right)
    return merged


def build_sast_candidate_pairs(
    left_findings: list[dict[str, Any]],
    right_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    for left in sort_findings_for_llm(left_findings):
        left_path = normalize_path(left.get("file_path"))
        left_line = safe_int(left.get("line_number"))
        left_cwe = normalize_identifier(left.get("cwe_id"))
        left_rule = normalize_identifier(left.get("rule_id"))

        best: dict[str, Any] | None = None
        for right in sort_findings_for_llm(right_findings):
            right_path = normalize_path(right.get("file_path"))
            if not left_path or not right_path or left_path != right_path:
                continue

            right_line = safe_int(right.get("line_number"))
            right_cwe = normalize_identifier(right.get("cwe_id"))
            right_rule = normalize_identifier(right.get("rule_id"))
            title_similarity = jaccard_similarity(
                (left.get("title"), left.get("description"), left.get("rule_id")),
                (right.get("title"), right.get("description"), right.get("rule_id")),
            )
            line_diff = None
            score = 0.0
            basis_parts: list[str] = ["file_path"]

            if left_line is not None and right_line is not None:
                line_diff = abs(left_line - right_line)
                if line_diff <= SAST_LLM_CANDIDATE_LINE_DISTANCE:
                    score += 0.62 if line_diff <= 2 else 0.56
                    basis_parts.append("nearby_line")

            if left_cwe and right_cwe and left_cwe == right_cwe:
                score += 0.22
                basis_parts.append("cwe")

            if left_rule and right_rule and left_rule == right_rule:
                score += 0.18
                basis_parts.append("rule_id")

            if title_similarity >= 0.22:
                score += min(0.18, title_similarity * 0.22)
                basis_parts.append("title_similarity")

            if score < 0.56:
                continue

            candidate = {
                "left_id": left.get("id"),
                "right_id": right.get("id"),
                "left": left,
                "right": right,
                "heuristic_score": round(min(score, 0.95), 3),
                "heuristic_basis": "+".join(basis_parts),
                "line_diff": line_diff,
                "title_similarity": round(title_similarity, 3),
            }
            if best is None or candidate["heuristic_score"] > best["heuristic_score"]:
                best = candidate

        if best is not None:
            best["candidate_id"] = f"sast-candidate-{len(candidates) + 1}"
            candidates.append(best)

    candidates.sort(key=lambda item: item["heuristic_score"], reverse=True)
    return candidates[:MAX_LLM_MATCH_CANDIDATES]


def build_sca_candidate_pairs(
    left_findings: list[dict[str, Any]],
    right_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    for left in sort_findings_for_llm(left_findings):
        best: dict[str, Any] | None = None
        for right in sort_findings_for_llm(right_findings):
            package_score, package_basis = package_match_strength(
                left.get("package_name"),
                right.get("package_name"),
            )
            shared_vuln_id, vuln_basis = shared_vulnerability_identifier(left, right)
            title_similarity = jaccard_similarity(
                (
                    left.get("title"),
                    left.get("description"),
                    left.get("package_name"),
                    left.get("cve_id"),
                    left.get("rule_id"),
                ),
                (
                    right.get("title"),
                    right.get("description"),
                    right.get("package_name"),
                    right.get("cve_id"),
                    right.get("rule_id"),
                ),
            )

            score = 0.0
            basis_parts: list[str] = []

            if package_score >= 1.0:
                score += 0.42
                basis_parts.append(package_basis)
            elif package_score >= 0.90:
                score += 0.34
                basis_parts.append(package_basis)
            elif package_score >= 0.80:
                score += 0.28
                basis_parts.append(package_basis)

            if shared_vuln_id:
                score += 0.40
                basis_parts.append(vuln_basis or "vulnerability_id")

            if versions_overlap(left.get("package_version"), right.get("package_version")):
                score += 0.12
                basis_parts.append("package_version")

            if versions_overlap(left.get("fixed_version"), right.get("fixed_version")):
                score += 0.08
                basis_parts.append("fixed_version")

            if title_similarity >= 0.20:
                score += min(0.14, title_similarity * 0.18)
                basis_parts.append("title_similarity")

            left_path = normalize_path(left.get("file_path"))
            right_path = normalize_path(right.get("file_path"))
            if left_path and right_path and left_path == right_path:
                score += 0.08
                basis_parts.append("file_path")

            if score < 0.44:
                continue

            candidate = {
                "left_id": left.get("id"),
                "right_id": right.get("id"),
                "left": left,
                "right": right,
                "heuristic_score": round(min(score, 0.95), 3),
                "heuristic_basis": "+".join(basis_parts) or "weak_similarity",
                "title_similarity": round(title_similarity, 3),
            }
            if best is None or candidate["heuristic_score"] > best["heuristic_score"]:
                best = candidate

        if best is not None:
            best["candidate_id"] = f"sca-candidate-{len(candidates) + 1}"
            candidates.append(best)

    candidates.sort(key=lambda item: item["heuristic_score"], reverse=True)
    return candidates[:MAX_LLM_MATCH_CANDIDATES]


def build_match_candidates(
    stage: str,
    left_findings: list[dict[str, Any]],
    right_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if stage == "sast":
        return build_sast_candidate_pairs(left_findings, right_findings)
    if stage == "sca":
        return build_sca_candidate_pairs(left_findings, right_findings)
    return []


def apply_llm_candidate_matching(
    stage: str,
    prompt_file: Path,
    left_findings: list[dict[str, Any]],
    right_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    candidates = build_match_candidates(stage, left_findings, right_findings)
    if not candidates:
        return {
            "accepted_pairs": [],
            "candidate_decisions": [],
            "candidate_count": 0,
            "accepted_count": 0,
        }

    payload = {
        "mode": "match_adjudication",
        "stage": stage,
        "prompt_file": str(prompt_file),
        "match_candidates": [
            {
                "candidate_id": candidate["candidate_id"],
                "left": compact_finding(candidate["left"]),
                "right": compact_finding(candidate["right"]),
                "heuristics": {
                    "heuristic_score": candidate["heuristic_score"],
                    "heuristic_basis": candidate["heuristic_basis"],
                    "line_diff": candidate.get("line_diff"),
                    "title_similarity": candidate["title_similarity"],
                },
            }
            for candidate in candidates
        ],
    }
    analyzer_result = run_llm_analyzer(payload)
    candidate_decisions = analyzer_result.get("candidate_decisions", [])
    decision_map = {
        item.get("candidate_id"): item
        for item in candidate_decisions
        if isinstance(item, dict) and item.get("candidate_id")
    }

    accepted_pairs: list[dict[str, Any]] = []
    used_left_ids: set[str] = set()
    used_right_ids: set[str] = set()
    for candidate in sorted(candidates, key=lambda item: item["heuristic_score"], reverse=True):
        decision = decision_map.get(candidate["candidate_id"], {})
        if decision.get("decision") != "same":
            continue

        left_id = str(candidate["left_id"])
        right_id = str(candidate["right_id"])
        if left_id in used_left_ids or right_id in used_right_ids:
            continue

        used_left_ids.add(left_id)
        used_right_ids.add(right_id)
        accepted_pairs.append(
            {
                "candidate_id": candidate["candidate_id"],
                "left": candidate["left"],
                "right": candidate["right"],
                "heuristic_score": candidate["heuristic_score"],
                "heuristic_basis": candidate["heuristic_basis"],
                "decision": decision,
            }
        )

    return {
        "accepted_pairs": accepted_pairs,
        "candidate_decisions": candidate_decisions,
        "candidate_count": len(candidates),
        "accepted_count": len(accepted_pairs),
        "provider": analyzer_result.get("provider"),
        "model": analyzer_result.get("model"),
        "summary": analyzer_result.get("summary"),
    }


def match_score_sca(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, str]:
    package_score, package_basis = package_match_strength(left.get("package_name"), right.get("package_name"))
    shared_vuln_id, vuln_basis = shared_vulnerability_identifier(left, right)
    title_similarity = jaccard_similarity(
        (left.get("title"), left.get("description")),
        (right.get("title"), right.get("description")),
    )
    same_package_version = versions_overlap(left.get("package_version"), right.get("package_version"))
    same_fixed_version = versions_overlap(left.get("fixed_version"), right.get("fixed_version"))

    if shared_vuln_id and package_score >= 0.80:
        return 1.0, f"{package_basis}+{vuln_basis or 'vulnerability_id'}"
    if shared_vuln_id and same_package_version and title_similarity >= 0.45:
        return 0.84, f"{vuln_basis or 'vulnerability_id'}+package_version+title_similarity"
    if package_score >= 0.90 and same_fixed_version:
        return 0.82, f"{package_basis}+fixed_version"
    if package_score >= 0.80 and title_similarity >= 0.68:
        return 0.80, f"{package_basis}+title_similarity"
    if package_score >= 0.80 and same_package_version:
        return 0.78, f"{package_basis}+package_version"
    return 0.0, "no_strong_sca_match"


def match_score_dast(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, str]:
    left_path = normalize_url_path(left.get("url"))
    right_path = normalize_url_path(right.get("url"))
    left_param = normalize_identifier(left.get("parameter"))
    right_param = normalize_identifier(right.get("parameter"))
    left_cwe = normalize_identifier(left.get("cwe_id"))
    right_cwe = normalize_identifier(right.get("cwe_id"))
    left_rule = normalize_identifier(left.get("rule_id"))
    right_rule = normalize_identifier(right.get("rule_id"))
    title_similarity = jaccard_similarity(
        (left.get("title"), left.get("description")),
        (right.get("title"), right.get("description")),
    )

    if left_path and right_path and left_path == right_path and left_param and right_param and left_param == right_param:
        if left_cwe and right_cwe and left_cwe == right_cwe:
            return 0.95, "url_path+parameter+cwe"
        if title_similarity >= 0.65:
            return 0.85, "url_path+parameter+title_similarity"
    if left_path and right_path and left_path == right_path and left_rule and right_rule and left_rule == right_rule:
        return 0.82, "url_path+rule_id"
    if left_path and right_path and left_path == right_path and title_similarity >= 0.74:
        return 0.80, "url_path+title_similarity"
    return 0.0, "no_strong_dast_match"


def match_score_sast(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, str]:
    left_path = normalize_path(left.get("file_path"))
    right_path = normalize_path(right.get("file_path"))
    left_line = safe_int(left.get("line_number"))
    right_line = safe_int(right.get("line_number"))
    left_cwe = normalize_identifier(left.get("cwe_id"))
    right_cwe = normalize_identifier(right.get("cwe_id"))
    title_similarity = jaccard_similarity(
        (left.get("title"), left.get("description"), left.get("rule_id")),
        (right.get("title"), right.get("description"), right.get("rule_id")),
    )

    same_path = bool(left_path and right_path and left_path == right_path)
    line_close = left_line is not None and right_line is not None and abs(left_line - right_line) <= 3

    if same_path and line_close and left_cwe and right_cwe and left_cwe == right_cwe:
        return 0.92, "file_path+line_proximity+cwe"
    if same_path and line_close and title_similarity >= 0.68:
        return 0.84, "file_path+line_proximity+title_similarity"
    if same_path and left_cwe and right_cwe and left_cwe == right_cwe:
        return 0.80, "file_path+cwe"
    if same_path and title_similarity >= 0.82:
        return 0.78, "file_path+title_similarity"
    return 0.0, "no_strong_sast_match"


def match_score_iac(left: dict[str, Any], right: dict[str, Any]) -> tuple[float, str]:
    left_path = normalize_path(left.get("file_path"))
    right_path = normalize_path(right.get("file_path"))
    left_line = safe_int(left.get("line_number"))
    right_line = safe_int(right.get("line_number"))
    title_similarity = jaccard_similarity(
        (left.get("title"), left.get("description"), left.get("rule_id")),
        (right.get("title"), right.get("description"), right.get("rule_id")),
    )
    same_path = bool(left_path and right_path and left_path == right_path)
    line_close = left_line is not None and right_line is not None and abs(left_line - right_line) <= 8

    if same_path and line_close and title_similarity >= 0.70:
        return 0.82, "file_path+line_proximity+title_similarity"
    if same_path and title_similarity >= 0.84:
        return 0.78, "file_path+title_similarity"
    return 0.0, "no_strong_iac_match"


def match_score(stage: str, left: dict[str, Any], right: dict[str, Any]) -> tuple[float, str]:
    if stage == "sca":
        return match_score_sca(left, right)
    if stage == "dast":
        return match_score_dast(left, right)
    if stage == "sast":
        return match_score_sast(left, right)
    return match_score_iac(left, right)


def build_matching_output(
    stage: str,
    tool_items: list[dict[str, Any]],
    match_prompt_file: Path | None = None,
) -> dict[str, Any]:
    if len(tool_items) != 2:
        confirmed = sum_summaries(*(item["summary"] for item in tool_items))
        return {
            "matched_findings": [],
            "tool_a_only": [],
            "tool_b_only": [],
            "confirmed_findings": [],
            "confirmed_summary": confirmed,
            "mismatch_summary": empty_summary(),
            "combined_summary": confirmed,
            "matched_count": 0,
            "mismatch_count": 0,
            "mismatch_ratio": 0.0,
            "match_threshold": None,
            "collapsed_duplicate_count": 0,
            "llm_candidate_count": 0,
            "llm_assisted_match_count": 0,
            "llm_candidate_decisions": [],
        }

    left_item, right_item = tool_items
    threshold = MATCH_THRESHOLDS[stage]
    left_findings = list(left_item["findings"])
    right_findings = list(right_item["findings"])
    duplicate_collapse_count = 0

    if stage == "sast":
        left_findings, left_duplicate_count = collapse_sast_near_duplicates(left_findings)
        right_findings, right_duplicate_count = collapse_sast_near_duplicates(right_findings)
        duplicate_collapse_count = left_duplicate_count + right_duplicate_count
    elif stage == "sca":
        left_findings, left_duplicate_count = collapse_sca_duplicates(left_findings)
        right_findings, right_duplicate_count = collapse_sca_duplicates(right_findings)
        duplicate_collapse_count = left_duplicate_count + right_duplicate_count

    right_pool = list(enumerate(right_findings))
    matched_pairs: list[dict[str, Any]] = []
    confirmed_findings: list[dict[str, Any]] = []
    left_only: list[dict[str, Any]] = []

    for left in sort_findings_for_llm(left_findings):
        best_match: tuple[int, dict[str, Any], float, str] | None = None
        for index, candidate in right_pool:
            score, basis = match_score(stage, left, candidate)
            if score < threshold:
                continue
            if best_match is None or score > best_match[2]:
                best_match = (index, candidate, score, basis)

        if best_match is None:
            left_only.append(left)
            continue

        match_index, right, score, basis = best_match
        right_pool = [item for item in right_pool if item[0] != match_index]
        matched_pairs.append(
            {
                "match_score": round(score, 3),
                "match_basis": basis,
                "left": compact_finding(left),
                "right": compact_finding(right),
            }
        )
        confirmed_findings.append(merge_matched_finding(stage, left, right, score, basis))

    right_only = [finding for _, finding in right_pool]

    llm_candidate_matching = {
        "candidate_count": 0,
        "accepted_count": 0,
        "accepted_pairs": [],
        "candidate_decisions": [],
    }
    if stage in {"sast", "sca"} and match_prompt_file is not None and left_only and right_only:
        llm_candidate_matching = apply_llm_candidate_matching(
            stage,
            match_prompt_file,
            left_only,
            right_only,
        )
        if llm_candidate_matching["accepted_pairs"]:
            matched_left_ids = {str(pair["left"].get("id")) for pair in llm_candidate_matching["accepted_pairs"]}
            matched_right_ids = {str(pair["right"].get("id")) for pair in llm_candidate_matching["accepted_pairs"]}
            left_only = [finding for finding in left_only if str(finding.get("id")) not in matched_left_ids]
            right_only = [finding for finding in right_only if str(finding.get("id")) not in matched_right_ids]

            for pair in llm_candidate_matching["accepted_pairs"]:
                left = pair["left"]
                right = pair["right"]
                matched_pairs.append(
                    {
                        "match_score": pair["heuristic_score"],
                        "match_basis": f"llm:{pair['heuristic_basis']}",
                        "left": compact_finding(left),
                        "right": compact_finding(right),
                        "llm_decision": pair["decision"],
                    }
                )
                merged = merge_matched_finding(
                    stage,
                    left,
                    right,
                    pair["heuristic_score"],
                    f"llm:{pair['heuristic_basis']}",
                )
                merged["llm_match"] = True
                merged["llm_reason"] = pair["decision"].get("reason")
                confirmed_findings.append(merged)

    confirmed_summary = summarize_findings(confirmed_findings)
    mismatch_summary = summarize_findings(left_only + right_only)
    combined_summary = sum_summaries(confirmed_summary, mismatch_summary)
    mismatch_count = mismatch_summary["total"]
    combined_total = combined_summary["total"]

    return {
        "matched_findings": matched_pairs,
        "tool_a_only": left_only,
        "tool_b_only": right_only,
        "confirmed_findings": confirmed_findings,
        "confirmed_summary": confirmed_summary,
        "mismatch_summary": mismatch_summary,
        "combined_summary": combined_summary,
        "matched_count": len(matched_pairs),
        "mismatch_count": mismatch_count,
        "mismatch_ratio": round(mismatch_count / max(1, combined_total), 4),
        "match_threshold": threshold,
        "llm_candidate_count": llm_candidate_matching["candidate_count"],
        "llm_assisted_match_count": llm_candidate_matching["accepted_count"],
        "llm_candidate_decisions": llm_candidate_matching["candidate_decisions"][:25],
        "collapsed_duplicate_count": duplicate_collapse_count,
    }


def build_decision(stage: str, confirmed: dict[str, int]) -> tuple[str, list[str]]:
    thresholds = DEFAULT_THRESHOLDS[stage]
    reasons = []

    if confirmed["critical"] > thresholds["critical"]:
        reasons.append(
            f"confirmed critical findings {confirmed['critical']} exceed threshold {thresholds['critical']}"
        )
        return "fail", reasons

    if confirmed["high"] > thresholds["high"]:
        reasons.append(
            f"confirmed high findings {confirmed['high']} exceed threshold {thresholds['high']}"
        )
        return "fail", reasons

    if confirmed["high"] > 0:
        reasons.append(f"confirmed high findings present: {confirmed['high']}")

    if confirmed["medium"] > thresholds["medium_review"]:
        reasons.append(
            "confirmed medium findings "
            f"{confirmed['medium']} exceed review threshold {thresholds['medium_review']}"
        )

    if reasons:
        return "review", reasons

    return "pass", ["confirmed findings are within configured thresholds"]


def build_llm_payload(
    stage: str,
    gate_prompt_file: Path,
    tool_items: list[dict[str, Any]],
    matching: dict[str, Any],
) -> dict[str, Any]:
    unmatched_left = sort_findings_for_llm(matching["tool_a_only"])[:MAX_LLM_FINDINGS_PER_TOOL]
    unmatched_right = sort_findings_for_llm(matching["tool_b_only"])[:MAX_LLM_FINDINGS_PER_TOOL]

    return {
        "stage": stage,
        "prompt_file": str(gate_prompt_file),
        "tool_summaries": [
            {
                "tool": item["tool"],
                "executed": item["executed"],
                "disabled_reason": item["disabled_reason"],
                "summary": item["summary"],
            }
            for item in tool_items
        ],
        "confirmed_summary": matching["confirmed_summary"],
        "mismatch_summary": matching["mismatch_summary"],
        "combined_summary": matching["combined_summary"],
        "divergence_ratio": matching["mismatch_ratio"],
        "matching": {
            "matched_count": matching["matched_count"],
            "mismatch_count": matching["mismatch_count"],
            "match_threshold": matching["match_threshold"],
        },
        "unmatched_findings": {
            tool_items[0]["tool"]: [compact_finding(finding) for finding in unmatched_left],
            tool_items[1]["tool"]: [compact_finding(finding) for finding in unmatched_right],
        },
        "unmatched_truncated": {
            tool_items[0]["tool"]: max(0, len(matching["tool_a_only"]) - len(unmatched_left)),
            tool_items[1]["tool"]: max(0, len(matching["tool_b_only"]) - len(unmatched_right)),
        },
    }


def skipped_llm_result(reason: str) -> dict[str, Any]:
    return {
        "component": "analyzer",
        "provider": "skipped",
        "model": None,
        "recommended_decision": "pass",
        "confidence": "high",
        "summary": reason,
        "reasons": [reason],
        "provider_notes": None,
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "openai_configured": bool(os.getenv("OPENAI_API_KEY", "").strip()),
        "attempted_providers": [],
    }


def apply_llm_recommendation(
    decision: str,
    reasons: list[str],
    analyzer_result: dict[str, Any],
    mismatch_count: int,
) -> tuple[str, list[str]]:
    llm_decision = str(analyzer_result.get("recommended_decision", "")).strip().lower()
    llm_summary = str(analyzer_result.get("summary", "")).strip()
    llm_reasons = analyzer_result.get("reasons", [])
    provider = str(analyzer_result.get("provider", "")).strip().lower()

    if mismatch_count > 0:
        reasons.append(f"unmatched findings requiring adjudication: {mismatch_count}")

    if llm_summary:
        reasons.append(f"llm summary: {llm_summary}")

    if isinstance(llm_reasons, list):
        for reason in llm_reasons[:3]:
            text = str(reason).strip()
            if text:
                reasons.append(f"llm reason: {text}")

    if mismatch_count <= 0:
        return decision, reasons

    if provider in {"fallback", "skipped"}:
        if decision == "pass":
            decision = "review"
        reasons.append("llm adjudication was unavailable for unmatched findings")
        return decision, reasons

    if llm_decision == "fail":
        decision = "fail"
        reasons.append("llm recommended fail for unmatched findings")
    elif llm_decision == "review" and decision == "pass":
        decision = "review"
        reasons.append("llm recommended manual review for unmatched findings")

    return decision, reasons


def emit_console_summary(output: dict[str, Any], output_path: Path) -> None:
    llm = output.get("llm_analysis", {})
    combined = output.get("combined_summary", {})
    confirmed = output.get("confirmed_summary", {})
    mismatch = output.get("mismatch_summary", {})
    matching = output.get("matching", {})

    print(f"LLM gate [{output['stage']}] completed")
    print(f"  output: {output_path}")
    print(f"  decision: {output['decision']}")
    print(f"  provider: {llm.get('provider')}")
    print(f"  model: {llm.get('model')}")
    print(f"  confidence: {llm.get('confidence')}")
    print(f"  gemini_configured: {llm.get('gemini_configured')}")
    print(f"  openai_configured: {llm.get('openai_configured')}")
    print(f"  attempted_providers: {', '.join(llm.get('attempted_providers', [])) or '-'}")
    print(f"  divergence_ratio: {output.get('divergence_ratio', 0)}")
    print(
        "  confirmed_summary: "
        f"critical={confirmed.get('critical', 0)}, "
        f"high={confirmed.get('high', 0)}, "
        f"medium={confirmed.get('medium', 0)}, "
        f"low={confirmed.get('low', 0)}, "
        f"info={confirmed.get('info', 0)}, "
        f"total={confirmed.get('total', 0)}"
    )
    print(
        "  mismatch_summary: "
        f"critical={mismatch.get('critical', 0)}, "
        f"high={mismatch.get('high', 0)}, "
        f"medium={mismatch.get('medium', 0)}, "
        f"low={mismatch.get('low', 0)}, "
        f"info={mismatch.get('info', 0)}, "
        f"total={mismatch.get('total', 0)}"
    )
    print(
        "  combined_summary: "
        f"critical={combined.get('critical', 0)}, "
        f"high={combined.get('high', 0)}, "
        f"medium={combined.get('medium', 0)}, "
        f"low={combined.get('low', 0)}, "
        f"info={combined.get('info', 0)}, "
        f"total={combined.get('total', 0)}"
    )
    print(
        f"  matches: matched={matching.get('matched_count', 0)} "
        f"mismatch={matching.get('mismatch_count', 0)} "
        f"mismatch_ratio={matching.get('mismatch_ratio', 0)} "
        f"collapsed_duplicates={matching.get('collapsed_duplicate_count', 0)} "
        f"llm_candidates={matching.get('llm_candidate_count', 0)} "
        f"llm_assisted_matches={matching.get('llm_assisted_match_count', 0)}"
    )

    for item in output.get("tool_summaries", []):
        summary = item.get("summary", {})
        executed = "yes" if item.get("executed", True) else "no"
        reason = item.get("disabled_reason") or "-"
        print(
            "  tool="
            f"{item.get('tool')} executed={executed} "
            f"critical={summary.get('critical', 0)} "
            f"high={summary.get('high', 0)} "
            f"medium={summary.get('medium', 0)} "
            f"low={summary.get('low', 0)} "
            f"info={summary.get('info', 0)} "
            f"total={summary.get('total', 0)} "
            f"reason={reason}"
        )

    for reason in output.get("reasons", [])[:8]:
        print(f"  reason: {reason}")


def escape_annotation(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit_github_annotation(output: dict[str, Any]) -> None:
    llm = output.get("llm_analysis", {})
    matching = output.get("matching", {})
    message = (
        f"stage={output['stage']}; decision={output['decision']}; "
        f"provider={llm.get('provider')}; model={llm.get('model')}; "
        f"confidence={llm.get('confidence')}; "
        f"gemini_configured={llm.get('gemini_configured')}; "
        f"openai_configured={llm.get('openai_configured')}; "
        f"matched={matching.get('matched_count', 0)}; "
        f"mismatch={matching.get('mismatch_count', 0)}; "
        f"collapsed_duplicates={matching.get('collapsed_duplicate_count', 0)}; "
        f"llm_candidates={matching.get('llm_candidate_count', 0)}; "
        f"llm_assisted_matches={matching.get('llm_assisted_match_count', 0)}"
    )
    reasons = output.get("reasons", [])
    if reasons:
        message += f"; top_reason={reasons[0]}"

    level = "notice"
    if output["decision"] == "review":
        level = "warning"
    elif output["decision"] == "fail":
        level = "error"

    print(f"::{level} title=LLM Gate {output['stage'].upper()}::{escape_annotation(message)}")


def write_step_summary(output: dict[str, Any]) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path:
        return

    llm = output.get("llm_analysis", {})
    combined = output.get("combined_summary", {})
    confirmed = output.get("confirmed_summary", {})
    mismatch = output.get("mismatch_summary", {})
    matching = output.get("matching", {})

    lines = [
        f"## LLM Gate `{output['stage']}`",
        "",
        f"- Decision: `{output['decision']}`",
        f"- Provider: `{llm.get('provider')}`",
        f"- Model: `{llm.get('model')}`",
        f"- Confidence: `{llm.get('confidence')}`",
        f"- Gemini configured: `{llm.get('gemini_configured')}`",
        f"- OpenAI configured: `{llm.get('openai_configured')}`",
        f"- Attempted providers: `{', '.join(llm.get('attempted_providers', [])) or '-'}`",
        f"- Mismatch ratio: `{matching.get('mismatch_ratio', 0)}`",
        f"- Matched findings: `{matching.get('matched_count', 0)}`",
        f"- Unmatched findings: `{matching.get('mismatch_count', 0)}`",
        f"- Collapsed duplicate findings: `{matching.get('collapsed_duplicate_count', 0)}`",
        f"- LLM match candidates: `{matching.get('llm_candidate_count', 0)}`",
        f"- LLM assisted matches: `{matching.get('llm_assisted_match_count', 0)}`",
        "",
        "**Confirmed Summary**",
        "",
        "| Critical | High | Medium | Low | Info | Total |",
        "| --- | --- | --- | --- | --- | --- |",
        (
            f"| {confirmed.get('critical', 0)} | {confirmed.get('high', 0)} | "
            f"{confirmed.get('medium', 0)} | {confirmed.get('low', 0)} | "
            f"{confirmed.get('info', 0)} | {confirmed.get('total', 0)} |"
        ),
        "",
        "**Mismatch Summary**",
        "",
        "| Critical | High | Medium | Low | Info | Total |",
        "| --- | --- | --- | --- | --- | --- |",
        (
            f"| {mismatch.get('critical', 0)} | {mismatch.get('high', 0)} | "
            f"{mismatch.get('medium', 0)} | {mismatch.get('low', 0)} | "
            f"{mismatch.get('info', 0)} | {mismatch.get('total', 0)} |"
        ),
        "",
        "**Combined Summary**",
        "",
        "| Critical | High | Medium | Low | Info | Total |",
        "| --- | --- | --- | --- | --- | --- |",
        (
            f"| {combined.get('critical', 0)} | {combined.get('high', 0)} | "
            f"{combined.get('medium', 0)} | {combined.get('low', 0)} | "
            f"{combined.get('info', 0)} | {combined.get('total', 0)} |"
        ),
        "",
        "**Tool Summaries**",
        "",
        "| Tool | Executed | Critical | High | Medium | Low | Info | Total | Disabled Reason |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    for item in output.get("tool_summaries", []):
        summary = item.get("summary", {})
        lines.append(
            f"| {item.get('tool')} | "
            f"{'yes' if item.get('executed', True) else 'no'} | "
            f"{summary.get('critical', 0)} | "
            f"{summary.get('high', 0)} | "
            f"{summary.get('medium', 0)} | "
            f"{summary.get('low', 0)} | "
            f"{summary.get('info', 0)} | "
            f"{summary.get('total', 0)} | "
            f"{item.get('disabled_reason') or '-'} |"
        )

    unmatched = output.get("unmatched_findings", {})
    if unmatched:
        lines.extend(["", "**Unmatched Findings Sent To LLM**", ""])
        for tool, findings in unmatched.items():
            lines.append(f"- `{tool}`: {len(findings)} findings")

    candidate_decisions = matching.get("llm_candidate_decisions", [])
    if candidate_decisions:
        lines.extend(
            [
                "",
                f"**{output['stage'].upper()} LLM Candidate Decisions**",
                "",
                "| Candidate | Decision | Confidence | Reason |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in candidate_decisions[:10]:
            lines.append(
                f"| {item.get('candidate_id') or '-'} | "
                f"{item.get('decision') or '-'} | "
                f"{item.get('confidence') or '-'} | "
                f"{(item.get('reason') or '-').replace('|', '&#124;')} |"
            )

    reasons = output.get("reasons", [])
    if reasons:
        lines.extend(["", "**Reasons**", ""])
        for reason in reasons[:8]:
            lines.append(f"- {reason}")

    provider_notes = llm.get("provider_notes")
    if provider_notes:
        lines.extend(["", f"**Provider notes:** {provider_notes}"])

    fallback_reason = llm.get("fallback_reason")
    if fallback_reason:
        lines.extend(["", f"**Fallback reason:** `{fallback_reason}`"])

    with Path(summary_path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    parsed_inputs = []
    for item in args.tool_input:
        if "=" not in item:
            raise ValueError(f"Invalid --tool-input value: {item}")
        tool, raw_path = item.split("=", 1)
        parsed_inputs.append((tool.strip(), Path(raw_path.strip())))

    gate_prompt_file = GATE_PROMPT_FILES[args.stage]
    match_prompt_file = MATCH_PROMPT_FILES[args.stage]
    tool_summaries = [normalize_tool_output(tool, path, args.stage) for tool, path in parsed_inputs]
    matching = build_matching_output(args.stage, tool_summaries, match_prompt_file)
    confirmed_summary = matching["confirmed_summary"]
    mismatch_summary = matching["mismatch_summary"]
    combined_summary = matching["combined_summary"]
    mismatch_count = matching["mismatch_count"]

    llm_needed = len(tool_summaries) == 2 and mismatch_count > 0 and all(
        item["executed"] for item in tool_summaries
    )
    if llm_needed:
        analyzer_payload = build_llm_payload(args.stage, gate_prompt_file, tool_summaries, matching)
        analyzer_result = run_llm_analyzer(analyzer_payload)
    else:
        skip_reason = "no unmatched findings required LLM adjudication"
        if mismatch_count > 0 and not all(item["executed"] for item in tool_summaries):
            skip_reason = "unmatched findings present but comparison tools did not both execute"
        analyzer_result = skipped_llm_result(skip_reason)

    decision, reasons = build_decision(args.stage, confirmed_summary)
    decision, reasons = apply_llm_recommendation(decision, reasons, analyzer_result, mismatch_count)

    for item in tool_summaries:
        if not item["executed"]:
            decision = "review"
            reasons.append(
                f"{item['tool']} did not execute: {item['disabled_reason'] or 'no reason provided'}"
            )

    advisory_mode = os.getenv("LLM_GATE_ADVISORY_MODE", "false").lower() == "true"
    if advisory_mode and decision == "fail":
        decision = "review"
        reasons.append("advisory mode enabled: fail downgraded to review")

    unmatched_findings = (
        {
            tool_summaries[0]["tool"]: [compact_finding(finding) for finding in matching["tool_a_only"]],
            tool_summaries[1]["tool"]: [compact_finding(finding) for finding in matching["tool_b_only"]],
        }
        if len(tool_summaries) == 2
        else {}
    )

    output = {
        "stage": args.stage,
        "prompt_file": str(gate_prompt_file),
        "tool_summaries": [
            {
                "tool": item["tool"],
                "path": item["path"],
                "summary": item["summary"],
                "executed": item["executed"],
                "disabled_reason": item["disabled_reason"],
                "finding_count": len(item["findings"]),
            }
            for item in tool_summaries
        ],
        "confirmed_summary": confirmed_summary,
        "mismatch_summary": mismatch_summary,
        "combined_summary": combined_summary,
        "divergence_ratio": matching["mismatch_ratio"],
        "matching": {
            "matched_count": matching["matched_count"],
            "mismatch_count": mismatch_count,
            "mismatch_ratio": matching["mismatch_ratio"],
            "match_threshold": matching["match_threshold"],
            "collapsed_duplicate_count": matching["collapsed_duplicate_count"],
            "llm_candidate_count": matching["llm_candidate_count"],
            "llm_assisted_match_count": matching["llm_assisted_match_count"],
            "llm_candidate_decisions": matching["llm_candidate_decisions"],
            "matched_pairs_sample": matching["matched_findings"][:25],
        },
        "unmatched_findings": unmatched_findings,
        "llm_analysis": analyzer_result,
        "decision": decision,
        "reasons": reasons,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    emit_console_summary(output, output_path)
    emit_github_annotation(output)
    write_step_summary(output)

    review_blocks = os.getenv("LLM_GATE_REVIEW_BLOCKS", "false").lower() == "true"
    if decision == "fail" or (decision == "review" and review_blocks):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
