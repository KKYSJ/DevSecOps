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
        max_per_tool = 10 if category == "IMAGE" else 5
        tool_count = 0
        for f in sorted_findings:
            if tool_count >= max_per_tool:
                break
            severity = (f.get("severity") or "MEDIUM").upper()
            # SAST/SCA는 Critical/High만, IaC/DAST/IMAGE는 전체
            if category not in ("IaC", "DAST", "IMAGE") and severity not in ("CRITICAL", "HIGH"):
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
                    "url": f.get("url", ""),
                    "cwe_id": f.get("cwe_id"),
                    "cve_id": f.get("cve_id"),
                    "description": full_desc[:400],
                },
                "finding_b": None,
            })

    return pairs


def normalize_api_base(url: str) -> str:
    """Accept either https://host or https://host/api/v1 and normalize to the API base."""
    normalized = url.strip().rstrip("/")
    if not normalized:
        return ""
    if normalized.endswith("/api/v1"):
        return normalized
    return f"{normalized}/api/v1"


def main():
    backend_url = normalize_api_base(
        (os.getenv("API_SERVER_URL", "") or os.getenv("BACKEND_URL", "")).strip()
    )
    commit_hash = os.getenv("COMMIT_SHA", "").strip()
    upload_key = os.getenv("SECUREFLOW_UPLOAD_KEY", "").strip()

    if not backend_url:
        print("API_SERVER_URL 미설정, 스킵")
        return

    all_stages = {"sast": "SAST", "sca": "SCA", "iac": "IaC", "dast": "DAST", "image": "IMAGE"}
    # gate 파일이 있는 stage만 처리 (CD에서는 DAST만 있을 수 있음)
    stages = {}
    for k, v in all_stages.items():
        gate_path = ROOT / f"scan-results/{k}-llm-gate/{k}-llm-gate.json"
        if gate_path.exists():
            stages[k] = v
    if not stages:
        print("처리할 gate 파일 없음")
        return
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

        # prompts.py로 프롬프트 생성 (15건씩 배치 처리)
        try:
            from engine.llm.prompts import build_cross_validation_prompt, parse_llm_response, _rule_based_fallback
            from engine.llm.client import call_llm

            BATCH_SIZE = 15
            analyzed = []
            for batch_start in range(0, len(pairs), BATCH_SIZE):
                batch = pairs[batch_start:batch_start + BATCH_SIZE]
                try:
                    prompt = build_cross_validation_prompt(category, batch)
                    response = call_llm(prompt)
                    batch_result = parse_llm_response(response, batch)
                    analyzed.extend(batch_result)
                    print(f"  배치 {batch_start//BATCH_SIZE+1}: {len(batch_result)}건 LLM 완료")
                except Exception as be:
                    print(f"  배치 {batch_start//BATCH_SIZE+1}: 실패 ({be}), 룰 기반 폴백")
                    analyzed.extend(_rule_based_fallback(batch))
            print(f"  LLM 판정 완료: {len(analyzed)}건")

        except Exception as e:
            print(f"  LLM 호출 실패 ({e}), 룰 기반 폴백")
            from engine.llm.prompts import _rule_based_fallback
            analyzed = _rule_based_fallback(pairs)

        all_judgments[stage] = analyzed

    # 카테고리별 LLM 요약 생성
    summaries = {}
    for stage, analyzed in all_judgments.items():
        tp = [p for p in analyzed if p.get("judgement_code") == "TRUE_POSITIVE" and p.get("finding_b")]
        rv = [p for p in analyzed if not (p.get("judgement_code") == "TRUE_POSITIVE" and p.get("finding_b"))]
        tp_titles = [p.get("title_ko", "") for p in tp[:5]]
        rv_titles = [p.get("title_ko", "") for p in rv[:3]]

        summary_prompt = f"""너는 DevSecOps 보안 분석 전문가다. 아래 교차검증 결과를 한국어로 요약하라.

카테고리: {stage.upper()}
동시 탐지 (두 도구 모두 발견): {len(tp)}건
{chr(10).join(f'  - {t}' for t in tp_titles) if tp_titles else '  없음'}
단독 탐지 (한 도구만 발견): {len(rv)}건
{chr(10).join(f'  - {t}' for t in rv_titles) if rv_titles else '  없음'}

아래 JSON 형식으로만 응답하라:
{{"summary": "2~3문장 한국어 요약", "reasons": ["근거1", "근거2"]}}
"""
        try:
            from engine.llm.client import call_llm
            resp = call_llm(summary_prompt)
            import re
            json_match = re.search(r'\{[\s\S]+\}', resp)
            if json_match:
                sdata = json.loads(json_match.group(0))
                summaries[stage] = sdata
                print(f"  {stage} 요약 생성 완료")
        except Exception as e:
            print(f"  {stage} 요약 실패 ({e})")
            summaries[stage] = {
                "summary": f"동시 탐지 {len(tp)}건, 단독 탐지 {len(rv)}건이 확인되었습니다.",
                "reasons": []
            }

    # EC2로 전송
    if all_judgments:
        import urllib.request
        payload = json.dumps({
            "stage": "judgments",
            "commit_hash": commit_hash,
            "gate_result": {
                "type": "individual_judgments",
                "commit_hash": commit_hash,
                "summaries": summaries,
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

        url = f"{backend_url}/scans/gate-result"
        headers = {"Content-Type": "application/json"}
        if upload_key:
            headers["X-SecureFlow-Upload-Key"] = upload_key
        req = urllib.request.Request(url, data=payload, headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            print(f"\n개별 판정 결과 EC2 전송 완료: {resp.read().decode()}")
        except Exception as e:
            print(f"\nEC2 전송 실패: {e}")


if __name__ == "__main__":
    main()
