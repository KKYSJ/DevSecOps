"""
CI에서 LLM gate 결과를 기반으로 개별 취약점 한국어 판정을 수행합니다.
run_llm_gate.py의 매칭 결과를 가져와서 prompts.py 로직으로 Gemini에 판정 요청.
결과를 EC2 백엔드로 전송.
"""

import json
import os
import sys
from pathlib import Path

# 프로젝트 루트를 path에 추가
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))


def load_gate(stage: str) -> dict | None:
    """CI artifact에서 gate JSON을 로드합니다."""
    path = ROOT / f"scan-results/{stage}-llm-gate/{stage}-llm-gate.json"
    if not path.exists():
        print(f"  {stage}: gate 파일 없음 ({path})")
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def gate_to_pairs(gate: dict, category: str) -> list[dict]:
    """gate 결과에서 prompts.py 형식의 매칭 페어를 생성합니다."""
    pairs = []
    matching = gate.get("matching", {})

    # 1. 동시 탐지 (matched pairs)
    for mp in matching.get("matched_pairs_sample", []):
        left = mp.get("left", {})
        right = mp.get("right", {})
        severity = left.get("severity") or right.get("severity") or "MEDIUM"
        pairs.append({
            "category": category,
            "severity": severity.upper(),
            "finding_a": {
                "tool": left.get("tool", ""),
                "category": category,
                "severity": (left.get("severity") or "MEDIUM").upper(),
                "title": left.get("title", ""),
                "file_path": left.get("file_path", ""),
                "line_number": left.get("line_number"),
                "cwe_id": left.get("cwe_id"),
                "cve_id": left.get("cve_id"),
                "description": left.get("description", "")[:200],
            },
            "finding_b": {
                "tool": right.get("tool", ""),
                "category": category,
                "severity": (right.get("severity") or "MEDIUM").upper(),
                "title": right.get("title", ""),
                "file_path": right.get("file_path", ""),
                "line_number": right.get("line_number"),
                "cwe_id": right.get("cwe_id"),
                "cve_id": right.get("cve_id"),
                "description": right.get("description", "")[:200],
            },
        })

    # 2. 단독 탐지 — 도구당 심각도 순 상위 5건
    _SEV = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unmatched = gate.get("unmatched_findings", {})
    for tool_name, findings in unmatched.items():
        if not isinstance(findings, list):
            continue
        # 심각도 순 정렬
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEV.get((f.get("severity") or "LOW").upper(), 9)
        )
        tool_count = 0
        for f in sorted_findings:
            if tool_count >= 5:
                break
            severity = (f.get("severity") or "MEDIUM").upper()
            # SAST/SCA는 Critical/High만, IaC/DAST는 전체
            if category not in ("IaC", "DAST") and severity not in ("CRITICAL", "HIGH"):
                continue
            tool_count += 1
            # title + description 합쳐서 LLM에 충분한 맥락 제공
            title = f.get("title", "")
            desc = f.get("description") or ""
            full_desc = f"{title}. {desc}" if desc and desc != title else title
            pairs.append({
                "category": category,
                "severity": severity,
                "finding_a": {
                    "tool": f.get("tool", tool_name),
                    "category": category,
                    "severity": severity,
                    "title": title,
                    "file_path": f.get("file_path", ""),
                    "line_number": f.get("line_number"),
                    "cwe_id": f.get("cwe_id"),
                    "cve_id": f.get("cve_id"),
                    "description": full_desc[:400],
                },
                "finding_b": None,
            })

    return pairs


def main():
    backend_url = os.getenv("BACKEND_URL", "").strip()
    commit_hash = os.getenv("COMMIT_SHA", "").strip()

    if not backend_url:
        print("BACKEND_URL 미설정, 스킵")
        return

    stages = {"sast": "SAST", "sca": "SCA", "iac": "IaC", "dast": "DAST"}
    all_judgments = {}

    for stage, category in stages.items():
        print(f"\n=== {stage.upper()} 개별 판정 ===")
        gate = load_gate(stage)
        if not gate:
            continue

        pairs = gate_to_pairs(gate, category)
        if not pairs:
            print(f"  매칭 페어 없음, 스킵")
            continue

        print(f"  매칭 페어 {len(pairs)}건 (동시탐지 + 단독 Critical/High)")

        # prompts.py로 프롬프트 생성
        try:
            from engine.llm.prompts import build_cross_validation_prompt, parse_llm_response, _rule_based_fallback
            from engine.llm.client import call_llm

            prompt = build_cross_validation_prompt(category, pairs)
            response = call_llm(prompt)
            analyzed = parse_llm_response(response, pairs)
            print(f"  LLM 판정 완료: {len(analyzed)}건")

        except Exception as e:
            print(f"  LLM 호출 실패 ({e}), 룰 기반 폴백")
            from engine.llm.prompts import _rule_based_fallback
            analyzed = _rule_based_fallback(pairs)

        all_judgments[stage] = analyzed

    # EC2로 전송
    if all_judgments:
        import urllib.request
        payload = json.dumps({
            "stage": "judgments",
            "commit_hash": commit_hash,
            "gate_result": {
                "type": "individual_judgments",
                "commit_hash": commit_hash,
                "judgments": {
                    stage: [
                        {
                            "category": p.get("category"),
                            "severity": p.get("severity"),
                            "judgement_code": p.get("judgement_code", "REVIEW_NEEDED"),
                            "confidence": p.get("confidence_level", "MED"),
                            "title_ko": p.get("title_ko", ""),
                            "risk_summary": p.get("risk_summary", ""),
                            "reason": p.get("reason", ""),
                            "action_text": p.get("action_text", ""),
                            "reassessed_severity": p.get("reassessed_severity", p.get("severity")),
                            "finding_a": p.get("finding_a"),
                            "finding_b": p.get("finding_b"),
                        }
                        for p in pairs_list
                    ]
                    for stage, pairs_list in all_judgments.items()
                },
            },
        }).encode("utf-8")

        url = f"{backend_url}/api/v1/scans/gate-result"
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            print(f"\n개별 판정 결과 EC2 전송 완료: {resp.read().decode()}")
        except Exception as e:
            print(f"\nEC2 전송 실패: {e}")


if __name__ == "__main__":
    main()
