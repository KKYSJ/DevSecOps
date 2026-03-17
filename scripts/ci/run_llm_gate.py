#!/usr/bin/env python3
"""Summarize security tool outputs and produce a stage gate decision."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from backend.app.services.llm.analyzer import run as run_llm_analyzer


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
PROMPT_FILES = {
    "iac": Path("engine/llm/iac_prompt.txt"),
    "sast": Path("engine/llm/sast_prompt.txt"),
    "sca": Path("engine/llm/sca_prompt.txt"),
    "dast": Path("engine/llm/dast_prompt.txt"),
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=sorted(PROMPT_FILES))
    parser.add_argument(
        "--tool-input",
        action="append",
        default=[],
        help="Provide tool=input.json pairs, e.g. semgrep=artifacts/semgrep.json",
    )
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load_json(path: Path) -> Any:
    content = path.read_text(encoding="utf-8").strip()
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


def add_finding(summary: dict[str, int], severity: str) -> None:
    level = normalize_severity(severity)
    summary["total"] += 1
    summary[level] += 1


def summarize_semgrep(data: dict[str, Any]) -> dict[str, int]:
    summary = empty_summary()
    for result in data.get("results", []):
        severity = result.get("extra", {}).get("severity", "warning")
        add_finding(summary, severity)
    return summary


def summarize_sonarqube(data: dict[str, Any]) -> dict[str, int]:
    summary = empty_summary()
    for issue in data.get("issues", []):
        if issue.get("type") not in ("VULNERABILITY", None):
            continue
        add_finding(summary, issue.get("severity", "major"))
    return summary


def summarize_depcheck(data: dict[str, Any]) -> dict[str, int]:
    summary = empty_summary()
    for dependency in data.get("dependencies", []):
        for vuln in dependency.get("vulnerabilities", []):
            severity = (
                vuln.get("cvssv3", {}).get("baseSeverity")
                or vuln.get("cvssv2", {}).get("severity")
                or vuln.get("severity")
                or "medium"
            )
            add_finding(summary, severity)
    return summary


def summarize_trivy(data: Any) -> dict[str, int]:
    summary = empty_summary()
    results = data.get("Results", []) if isinstance(data, dict) else []
    for result in results:
        for vuln in result.get("Vulnerabilities", []) or []:
            add_finding(summary, vuln.get("Severity", "medium"))
        for misconfig in result.get("Misconfigurations", []) or []:
            add_finding(summary, misconfig.get("Severity", "medium"))
    return summary


def summarize_checkov(data: dict[str, Any]) -> dict[str, int]:
    summary = empty_summary()
    failed = data.get("results", {}).get("failed_checks", [])
    for check in failed:
        severity = check.get("severity") or check.get("check_result", {}).get("severity") or "high"
        add_finding(summary, severity)
    return summary


def summarize_tfsec(data: dict[str, Any]) -> dict[str, int]:
    summary = empty_summary()
    for result in data.get("results", []):
        add_finding(summary, result.get("severity", "medium"))
    return summary


def summarize_zap(data: dict[str, Any]) -> dict[str, int]:
    summary = empty_summary()
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", []) or [{}]
            for _ in instances:
                add_finding(summary, alert.get("riskcode", "2"))
    return summary


def summarize_nuclei(data: Any) -> dict[str, int]:
    summary = empty_summary()
    records = data if isinstance(data, list) else [data]
    for record in records:
        if not isinstance(record, dict):
            continue
        severity = record.get("info", {}).get("severity") or record.get("severity") or "medium"
        add_finding(summary, severity)
    return summary


TOOL_SUMMARIZERS = {
    "semgrep": summarize_semgrep,
    "sonarqube": summarize_sonarqube,
    "depcheck": summarize_depcheck,
    "trivy": summarize_trivy,
    "checkov": summarize_checkov,
    "tfsec": summarize_tfsec,
    "zap": summarize_zap,
    "nuclei": summarize_nuclei,
}


def summarize_tool(tool: str, path: Path) -> dict[str, Any]:
    if tool not in TOOL_SUMMARIZERS:
        raise ValueError(f"Unsupported tool: {tool}")

    data = load_json(path)
    disabled = isinstance(data, dict) and data.get("tool_disabled", False)
    summary = empty_summary() if disabled else TOOL_SUMMARIZERS[tool](data)
    return {
        "tool": tool,
        "path": str(path),
        "summary": summary,
        "executed": not disabled,
        "disabled_reason": data.get("reason") if disabled and isinstance(data, dict) else None,
    }


def combine_summaries(items: list[dict[str, Any]]) -> dict[str, int]:
    combined = empty_summary()
    for item in items:
        for key in combined:
            combined[key] += item["summary"][key]
    return combined


def build_decision(stage: str, combined: dict[str, int], divergence: float) -> tuple[str, list[str]]:
    thresholds = DEFAULT_THRESHOLDS[stage]
    reasons = []

    if combined["critical"] > thresholds["critical"]:
        reasons.append(
            f"critical findings {combined['critical']} exceed threshold {thresholds['critical']}"
        )
        return "fail", reasons

    if combined["high"] > thresholds["high"]:
        reasons.append(f"high findings {combined['high']} exceed threshold {thresholds['high']}")
        return "fail", reasons

    if combined["high"] > 0:
        reasons.append(f"high findings present: {combined['high']}")

    if combined["medium"] > thresholds["medium_review"]:
        reasons.append(
            f"medium findings {combined['medium']} exceed review threshold {thresholds['medium_review']}"
        )

    if divergence > 0.6:
        reasons.append(f"tool divergence ratio is high: {divergence:.2f}")

    if reasons:
        return "review", reasons

    return "pass", ["all findings are within configured thresholds"]


def main() -> int:
    args = parse_args()
    parsed_inputs = []
    for item in args.tool_input:
        if "=" not in item:
            raise ValueError(f"Invalid --tool-input value: {item}")
        tool, raw_path = item.split("=", 1)
        parsed_inputs.append((tool.strip(), Path(raw_path.strip())))

    tool_summaries = [summarize_tool(tool, path) for tool, path in parsed_inputs]
    combined = combine_summaries(tool_summaries)
    totals = [item["summary"]["total"] for item in tool_summaries]
    divergence = 0.0
    if len(totals) >= 2:
        divergence = abs(max(totals) - min(totals)) / max(1, max(totals))

    prompt_file = PROMPT_FILES[args.stage]
    analyzer_payload = {
        "stage": args.stage,
        "prompt_file": str(prompt_file),
        "tool_summaries": tool_summaries,
        "combined_summary": combined,
        "divergence_ratio": round(divergence, 4),
    }
    analyzer_result = run_llm_analyzer(analyzer_payload)
    decision, reasons = build_decision(args.stage, combined, divergence)

    for item in tool_summaries:
        if not item["executed"]:
            decision = "review"
            reasons.append(f"{item['tool']} did not execute: {item['disabled_reason'] or 'no reason provided'}")

    output = {
        "stage": args.stage,
        "prompt_file": str(prompt_file),
        "tool_summaries": tool_summaries,
        "combined_summary": combined,
        "divergence_ratio": round(divergence, 4),
        "llm_analysis": analyzer_result,
        "decision": decision,
        "reasons": reasons,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    review_blocks = os.getenv("LLM_GATE_REVIEW_BLOCKS", "false").lower() == "true"
    if decision == "fail" or (decision == "review" and review_blocks):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
