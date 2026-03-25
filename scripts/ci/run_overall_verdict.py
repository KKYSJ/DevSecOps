"""Build and upload an overall LLM verdict from per-stage gate results."""

import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, ".")

from engine.llm.client import call_llm


STAGES = ["iac", "sast", "sca", "image", "dast"]


def load_stage_details():
    stage_details = []

    for stage in STAGES:
        path = f"scan-results/{stage}-llm-gate/{stage}-llm-gate.json"
        if not os.path.exists(path):
            continue

        with open(path, encoding="utf-8") as file:
            gate = json.load(file)

        decision = gate.get("decision", "unknown")
        matching = gate.get("matching", {})
        matched = len(matching.get("matched_pairs_sample", []))
        unmatched = len(gate.get("unmatched_findings", []))
        summary = gate.get("llm_analysis", {}).get("summary", "")
        stage_details.append(
            f"[{stage.upper()}] gate={decision}, matched={matched}, "
            f"unmatched={unmatched}\n  summary: {summary[:150]}"
        )

    return stage_details


def build_prompt(stage_details, final_decision):
    return (
        "You are the final decision reviewer for a DevSecOps security pipeline.\n"
        "Below are the analyzed results from each security scan stage. "
        "Create a concise final verdict summary that reflects the gate result.\n\n"
        + "\n".join(stage_details)
        + "\n\n"
        + f"Final gate decision: {final_decision}\n\n"
        + "If the decision is ALLOW, explain why deployment can proceed and "
        "summarize the remaining risk level.\n"
        + "If the decision is BLOCK, explain why deployment must stop, which "
        "stage exceeded tolerance, and what should be addressed first.\n\n"
        + "Include:\n"
        + "1. The final decision and reason\n"
        + "2. A short summary of the main findings by stage\n"
        + "3. An overall security posture assessment\n\n"
        + 'Respond in JSON only: {"verdict": "5-8 sentence final summary"}'
    )


def generate_verdict(stage_details):
    has_fail = any("gate=fail" in detail for detail in stage_details)
    final_decision = "BLOCK" if has_fail else "ALLOW"

    print(f"Overall decision target: {len(stage_details)} stages, final={final_decision}")

    response = call_llm(build_prompt(stage_details, final_decision))
    match = re.search(r"\{[\s\S]+\}", response)
    if match:
        verdict_data = json.loads(match.group(0))
        print("Overall verdict generated")
    else:
        verdict_data = {"verdict": "Failed to generate overall verdict"}
        print("Failed to parse LLM response")

    return verdict_data


def upload_verdict(verdict_data):
    api_server_url = os.getenv("API_SERVER_URL", "").strip().rstrip("/")
    upload_key = os.getenv("SECUREFLOW_UPLOAD_KEY", "").strip()
    commit = os.getenv("COMMIT_SHA", "").strip()

    if not api_server_url:
        print("API_SERVER_URL is not set, skipping upload")
        return

    payload = json.dumps(
        {
            "stage": "overall-verdict",
            "commit_hash": commit,
            "gate_result": {
                "type": "overall_verdict",
                "summaries": {"_overall": verdict_data},
            },
        }
    ).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if upload_key:
        headers["X-SecureFlow-Upload-Key"] = upload_key

    request = urllib.request.Request(
        f"{api_server_url}/api/v1/scans/gate-result",
        data=payload,
        headers=headers,
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            print(f"Upload complete: {response.read().decode()}")
    except Exception as exc:
        print(f"Upload failed: {exc}")


def main():
    stage_details = load_stage_details()
    if not stage_details:
        print("No gate files found, skipping verdict")
        sys.exit(0)

    verdict_data = generate_verdict(stage_details)
    print(f"  verdict: {verdict_data.get('verdict', '')[:100]}...")
    upload_verdict(verdict_data)


if __name__ == "__main__":
    main()
