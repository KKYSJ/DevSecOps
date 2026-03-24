#!/usr/bin/env python3
"""Evaluate whether the pipeline can proceed to production."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import boto3

REPO_ROOT = Path(__file__).resolve().parents[2]
ISMSP_ROOT = REPO_ROOT / "ismsp"
if str(ISMSP_ROOT) not in sys.path:
    sys.path.insert(0, str(ISMSP_ROOT))

from ismsp.config import DEFAULT_PROFILE, DEFAULT_REGION
from ismsp.checker.aws_checker import AWSChecker
from ismsp.checker.evaluator import Evaluator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True, choices=["staging", "production"])
    parser.add_argument("--target-url", default="")
    parser.add_argument("--gate-input", action="append", default=[])
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return {}
    return json.loads(content)


def build_evaluator_result(report: dict | None) -> dict | None:
    if not isinstance(report, dict):
        return None

    summary = report.get("summary", {})
    automated_results = report.get("automated_results", [])
    non_compliant = [
        {
            "isms_p_id": item.get("isms_p_id"),
            "isms_p_name": item.get("isms_p_name"),
            "status": item.get("status"),
            "source": item.get("source"),
        }
        for item in automated_results
        if item.get("status") == "NON_COMPLIANT"
    ]

    return {
        "summary": summary,
        "metadata": report.get("metadata", {}),
        "manual_items_count": len(report.get("manual_items", [])),
        "non_compliant_items": non_compliant[:20],
    }


def has_aws_credentials() -> bool:
    return bool(
        os.getenv("AWS_ACCESS_KEY_ID")
        or os.getenv("AWS_PROFILE")
        or os.getenv("AWS_ROLE_ARN")
        or os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
    )


def run_isms_checks(region: str, profile: str | None = None) -> dict:
    session = boto3.Session(profile_name=profile, region_name=region)
    checker = AWSChecker(session, region=region)
    evaluator = Evaluator(checker)
    evaluator.load_mappings()
    return evaluator.run()


def emit_console_summary(output: dict, output_path: Path) -> None:
    evidence = output.get("evidence", {})
    print(f"ISMS-P gate [{output['environment']}] completed")
    print(f"  output: {output_path}")
    print(f"  decision: {output['decision']}")
    print(f"  target_url: {output.get('target_url')}")
    print(f"  aws_region: {evidence.get('aws_region')}")
    print(f"  aws_credentials_configured: {evidence.get('aws_credentials_configured')}")
    print(f"  checker_status: {evidence.get('checker_status')}")
    print(f"  gate_decisions: {', '.join(evidence.get('gate_decisions', [])) or '-'}")

    for reason in output.get("reasons", [])[:8]:
        print(f"  reason: {reason}")


def escape_annotation(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit_github_annotation(output: dict) -> None:
    message = (
        f"environment={output['environment']}; decision={output['decision']}; "
        f"target_url={output.get('target_url') or '-'}"
    )
    reasons = output.get("reasons", [])
    if reasons:
        message += f"; top_reason={reasons[0]}"

    level = "notice"
    if output["decision"] == "review":
        level = "warning"
    elif output["decision"] == "fail":
        level = "error"

    print(f"::{level} title=ISMS-P Gate::{escape_annotation(message)}")


def write_step_summary(output: dict) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path:
        return

    evidence = output.get("evidence", {})
    lines = [
        f"## ISMS-P Gate `{output['environment']}`",
        "",
        f"- Decision: `{output['decision']}`",
        f"- Target URL: `{output.get('target_url') or '-'}`",
        f"- AWS region: `{evidence.get('aws_region')}`",
        f"- AWS credentials configured: `{evidence.get('aws_credentials_configured')}`",
        f"- Checker status: `{evidence.get('checker_status')}`",
        "",
        "**Upstream Gate Decisions**",
        "",
    ]

    gate_decisions = evidence.get("gate_decisions", [])
    if gate_decisions:
        for gate_decision in gate_decisions:
            lines.append(f"- `{gate_decision}`")
    else:
        lines.append("- None")

    reasons = output.get("reasons", [])
    if reasons:
        lines.extend(["", "**Reasons**", ""])
        for reason in reasons[:8]:
            lines.append(f"- {reason}")

    checker_error = evidence.get("checker_error")
    if checker_error:
        lines.extend(["", "**Checker Error**", "", f"- {checker_error}"])

    checker_result = output.get("checker_result")
    if checker_result is not None:
        lines.extend(["", "**Checker Result**", "", "```json", json.dumps(checker_result, indent=2), "```"])

    evaluator_result = output.get("evaluator_result")
    if evaluator_result is not None:
        lines.extend(["", "**Evaluator Result**", "", "```json", json.dumps(evaluator_result, indent=2), "```"])

    with Path(summary_path).open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    missing_gate_inputs: list[str] = []
    gate_summaries = []
    for item in args.gate_input:
        path = Path(item)
        if not path.exists():
            missing_gate_inputs.append(str(path))
            continue
        gate_summaries.append(load_json(path))
    gate_decisions = [item.get("decision", "review") for item in gate_summaries]
    aws_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or DEFAULT_REGION
    aws_profile = os.getenv("AWS_PROFILE") or DEFAULT_PROFILE
    checker_error = None
    checker_result = None

    if has_aws_credentials():
        try:
            checker_result = run_isms_checks(region=aws_region, profile=aws_profile)
        except Exception as exc:
            checker_error = str(exc)
    else:
        checker_error = "AWS credentials are not configured for the ISMS-P gate job"

    evaluator_result = build_evaluator_result(checker_result)
    summary = checker_result.get("summary", {}) if isinstance(checker_result, dict) else {}
    non_compliant = int(summary.get("non_compliant", 0) or 0)
    insufficient_data = int(summary.get("insufficient_data", 0) or 0)
    compliance_rate = summary.get("compliance_rate_pct")

    checker_status = "completed" if checker_result is not None else "unavailable"
    if checker_error:
        checker_status = "error" if has_aws_credentials() else "skipped"

    evidence = {
        "environment": args.environment,
        "target_url": args.target_url or None,
        "gate_decisions": gate_decisions,
        "aws_region": aws_region,
        "aws_profile": aws_profile,
        "aws_credentials_configured": has_aws_credentials(),
        "checker_status": checker_status,
        "checker_error": checker_error,
        "missing_gate_inputs": missing_gate_inputs,
        "non_compliant": non_compliant,
        "insufficient_data": insufficient_data,
        "compliance_rate_pct": compliance_rate,
    }

    if "fail" in gate_decisions:
        decision = "fail"
        reasons = ["a prior LLM security gate returned fail"]
    elif missing_gate_inputs:
        decision = "review"
        reasons = [f"required gate input is missing: {', '.join(missing_gate_inputs)}"]
    elif checker_error:
        decision = "review"
        reasons = [checker_error]
    elif non_compliant > 0:
        decision = "review"
        reasons = [f"ISMS-P automated checks found {non_compliant} non-compliant item(s)"]
        if compliance_rate is not None:
            reasons.append(f"current automated compliance rate is {compliance_rate}%")
    elif insufficient_data > 0:
        decision = "review"
        reasons = [f"ISMS-P automated checks returned {insufficient_data} insufficient-data item(s)"]
    elif args.environment == "production" and "review" in gate_decisions:
        decision = "review"
        reasons = ["security gates require review before production deployment"]
    else:
        decision = "pass"
        reasons = ["ISMS-P automated checks completed without non-compliant items"]

    output = {
        "environment": args.environment,
        "target_url": args.target_url or None,
        "decision": decision,
        "reasons": reasons,
        "checker_result": checker_result,
        "evaluator_result": evaluator_result,
        "evidence": evidence,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    emit_console_summary(output, output_path)
    emit_github_annotation(output)
    write_step_summary(output)

    if decision == "fail":
        return 1
    if args.environment == "production" and decision == "review":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
