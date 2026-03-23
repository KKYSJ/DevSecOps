from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

STAGE_CATEGORIES = {
    "sast": "SAST",
    "sca": "SCA",
    "iac": "IaC",
    "dast": "DAST",
    "image": "IMAGE",
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def normalize_api_base(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if not normalized:
        return ""
    if normalized.endswith("/api/v1"):
        return normalized
    return f"{normalized}/api/v1"


def gate_path(stage: str) -> Path:
    return ROOT / f"scan-results/{stage}-llm-gate/{stage}-llm-gate.json"


def load_gate(stage: str) -> dict | None:
    path = gate_path(stage)
    if not path.exists():
        print(f"  {stage}: missing gate file ({path})")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def collect_pairs(gate: dict, category: str) -> list[dict]:
    pairs: list[dict] = []
    matching = gate.get("matching", {})

    for match in matching.get("matched_pairs_sample", []):
        left = match.get("left", {})
        right = match.get("right", {})
        severity = (left.get("severity") or right.get("severity") or "MEDIUM").upper()
        pairs.append(
            {
                "category": category,
                "severity": severity,
                "finding_a": {
                    "tool": left.get("tool", ""),
                    "category": category,
                    "severity": (left.get("severity") or "MEDIUM").upper(),
                    "title": left.get("title", ""),
                    "file_path": left.get("file_path", ""),
                    "line_number": left.get("line_number"),
                    "url": left.get("url", ""),
                    "cwe_id": left.get("cwe_id"),
                    "cve_id": left.get("cve_id"),
                    "description": str(left.get("description") or "")[:400],
                },
                "finding_b": {
                    "tool": right.get("tool", ""),
                    "category": category,
                    "severity": (right.get("severity") or "MEDIUM").upper(),
                    "title": right.get("title", ""),
                    "file_path": right.get("file_path", ""),
                    "line_number": right.get("line_number"),
                    "url": right.get("url", ""),
                    "cwe_id": right.get("cwe_id"),
                    "cve_id": right.get("cve_id"),
                    "description": str(right.get("description") or "")[:400],
                },
            }
        )

    unmatched = gate.get("unmatched_findings", {})
    for tool_name, findings in unmatched.items():
        if not isinstance(findings, list):
            continue

        sorted_findings = sorted(
            findings,
            key=lambda finding: SEVERITY_ORDER.get(
                str(finding.get("severity") or "LOW").upper(),
                9,
            ),
        )
        max_per_tool = 10 if category == "IMAGE" else 5
        added = 0

        for finding in sorted_findings:
            if added >= max_per_tool:
                break

            severity = str(finding.get("severity") or "MEDIUM").upper()
            if category not in {"IaC", "DAST", "IMAGE"} and severity not in {"CRITICAL", "HIGH"}:
                continue

            title = str(finding.get("title") or "")
            description = str(finding.get("description") or "")
            full_description = f"{title}. {description}" if description and description != title else title

            pairs.append(
                {
                    "category": category,
                    "severity": severity,
                    "finding_a": {
                        "tool": finding.get("tool", tool_name),
                        "category": category,
                        "severity": severity,
                        "title": title,
                        "file_path": finding.get("file_path", ""),
                        "line_number": finding.get("line_number"),
                        "url": finding.get("url", ""),
                        "cwe_id": finding.get("cwe_id"),
                        "cve_id": finding.get("cve_id"),
                        "description": full_description[:400],
                    },
                    "finding_b": None,
                }
            )
            added += 1

    return pairs


def summarize_judgements(stage: str, judged_pairs: list[dict]) -> dict:
    true_positive_pairs = [
        pair
        for pair in judged_pairs
        if pair.get("judgement_code") == "TRUE_POSITIVE" and pair.get("finding_b")
    ]
    review_pairs = [
        pair
        for pair in judged_pairs
        if not (pair.get("judgement_code") == "TRUE_POSITIVE" and pair.get("finding_b"))
    ]

    tp_titles = [pair.get("title_ko", "") for pair in true_positive_pairs[:5] if pair.get("title_ko")]
    review_titles = [pair.get("title_ko", "") for pair in review_pairs[:3] if pair.get("title_ko")]

    summary_prompt = f"""
You are summarizing SecureFlow individual vulnerability adjudication results.
Return JSON only with this schema:
{{"summary": "2-3 sentence summary in Korean", "reasons": ["reason 1", "reason 2"]}}

Stage: {stage.upper()}
Confirmed by multiple tools: {len(true_positive_pairs)}
Sample confirmed titles:
{chr(10).join(f"- {title}" for title in tp_titles) if tp_titles else "- none"}

Single-tool or review-needed findings: {len(review_pairs)}
Sample review-needed titles:
{chr(10).join(f"- {title}" for title in review_titles) if review_titles else "- none"}
""".strip()

    try:
        import re

        from engine.llm.client import call_llm

        response = call_llm(summary_prompt)
        json_match = re.search(r"\{[\s\S]+\}", response)
        if json_match:
            return json.loads(json_match.group(0))
    except Exception as exc:  # noqa: BLE001
        print(f"  {stage}: failed to build summary via LLM ({exc})")

    return {
        "summary": (
            f"{stage.upper()} stage produced {len(true_positive_pairs)} confirmed cross-tool findings "
            f"and {len(review_pairs)} findings that still need review."
        ),
        "reasons": [],
    }


def upload_results(api_base: str, commit_hash: str, upload_key: str, payload: dict) -> None:
    url = f"{api_base}/scans/gate-result"
    headers = {"Content-Type": "application/json"}
    if upload_key:
        headers["X-SecureFlow-Upload-Key"] = upload_key

    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read().decode("utf-8", errors="replace")
        print(f"\nUploaded individual judgments: {body}")


def main() -> None:
    api_base = normalize_api_base(os.getenv("API_SERVER_URL", "") or os.getenv("BACKEND_URL", ""))
    commit_hash = os.getenv("COMMIT_SHA", "").strip()
    upload_key = os.getenv("SECUREFLOW_UPLOAD_KEY", "").strip()

    if not api_base:
        print("API_SERVER_URL is not configured; skipping individual judgments upload.")
        return

    stages = {
        stage: category
        for stage, category in STAGE_CATEGORIES.items()
        if gate_path(stage).exists()
    }
    if not stages:
        print("No gate files were found; skipping individual judgments.")
        return

    all_judgments: dict[str, list[dict]] = {}
    summaries: dict[str, dict] = {}

    for stage, category in stages.items():
        print(f"\n=== {stage.upper()} individual judgments ===")
        gate = load_gate(stage)
        if not gate:
            continue

        pairs = collect_pairs(gate, category)
        if not pairs:
            print("  No matched or high-priority unmatched findings to review.")
            continue

        print(f"  Candidate pairs: {len(pairs)}")

        try:
            from engine.llm.client import call_llm
            from engine.llm.prompts import (
                _rule_based_fallback,
                build_cross_validation_prompt,
                parse_llm_response,
            )

            judged_pairs: list[dict] = []
            batch_size = 15

            for batch_start in range(0, len(pairs), batch_size):
                batch = pairs[batch_start : batch_start + batch_size]
                batch_number = (batch_start // batch_size) + 1
                try:
                    prompt = build_cross_validation_prompt(category, batch)
                    response = call_llm(prompt)
                    parsed = parse_llm_response(response, batch)
                    judged_pairs.extend(parsed)
                    print(f"  Batch {batch_number}: {len(parsed)} judgments completed")
                except Exception as batch_exc:  # noqa: BLE001
                    print(f"  Batch {batch_number}: LLM failed ({batch_exc}); using fallback")
                    judged_pairs.extend(_rule_based_fallback(batch))

        except Exception as exc:  # noqa: BLE001
            print(f"  LLM pipeline failed ({exc}); using rule-based fallback")
            from engine.llm.prompts import _rule_based_fallback

            judged_pairs = _rule_based_fallback(pairs)

        print(f"  Final judgments: {len(judged_pairs)}")
        all_judgments[stage] = judged_pairs
        summaries[stage] = summarize_judgements(stage, judged_pairs)

    if not all_judgments:
        print("No judgments were produced; nothing to upload.")
        return

    payload = {
        "stage": "judgments",
        "commit_hash": commit_hash,
        "gate_result": {
            "type": "individual_judgments",
            "commit_hash": commit_hash,
            "summaries": summaries,
            "judgments": {
                stage: [
                    {
                        "category": pair.get("category"),
                        "severity": pair.get("severity"),
                        "judgement_code": pair.get("judgement_code", "REVIEW_NEEDED"),
                        "confidence": pair.get("confidence_level", "MED"),
                        "title_ko": pair.get("title_ko", ""),
                        "risk_summary": pair.get("risk_summary", ""),
                        "reason": pair.get("reason", ""),
                        "action_text": pair.get("action_text", ""),
                        "reassessed_severity": pair.get(
                            "reassessed_severity",
                            pair.get("severity"),
                        ),
                        "finding_a": pair.get("finding_a"),
                        "finding_b": pair.get("finding_b"),
                    }
                    for pair in judged_pairs
                ]
                for stage, judged_pairs in all_judgments.items()
            },
        },
    }

    try:
        upload_results(api_base, commit_hash, upload_key, payload)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"\nFailed to upload individual judgments: HTTP {exc.code}")
        if body:
            print(body[:1000])
    except Exception as exc:  # noqa: BLE001
        print(f"\nFailed to upload individual judgments: {exc}")


if __name__ == "__main__":
    main()
