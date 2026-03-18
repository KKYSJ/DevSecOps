#!/usr/bin/env python3
"""Evaluate whether the pipeline can proceed to production."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from backend.app.services.ismsp.checker import run as run_checker
from ismsp.checker.evaluator import evaluate


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True, choices=["staging", "production"])
    parser.add_argument("--target-url", default="")
    parser.add_argument("--gate-input", action="append", default=[])
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def load_json(path: Path) -> dict:
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return {}
    return json.loads(content)


def load_mapping(path: Path) -> list[dict]:
    data = load_json(path)
    if isinstance(data, dict):
        items = data.get("items", [])
        return items if isinstance(items, list) else []
    return data if isinstance(data, list) else []


def main() -> int:
    args = parse_args()
    gate_summaries = [load_json(Path(item)) for item in args.gate_input]
    gate_decisions = [item.get("decision", "review") for item in gate_summaries]

    mapping_path = Path("ismsp/mappings/isms_mapping.json")
    evidence = {
        "environment": args.environment,
        "target_url": args.target_url or None,
        "gate_decisions": gate_decisions,
        "mapping_exists": mapping_path.exists(),
        "mapping_path": str(mapping_path),
    }

    checker_result = run_checker(evidence)
    evaluator_mapping = load_mapping(mapping_path) if mapping_path.exists() else None
    evaluator_result = evaluate(evidence, mapping=evaluator_mapping)

    if "fail" in gate_decisions:
        decision = "fail"
        reasons = ["a prior LLM security gate returned fail"]
    elif args.environment == "production" and "review" in gate_decisions:
        decision = "review"
        reasons = ["security gates require review before production deployment"]
    elif not mapping_path.exists():
        decision = "review"
        reasons = ["ISMS-P mapping file is missing"]
    else:
        decision = "pass"
        reasons = ["ISMS-P evidence is present for the current release"]

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

    if decision == "fail":
        return 1
    if args.environment == "production" and decision == "review":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
