"""Overall verdict: 전체 stage gate 결과를 종합하여 LLM 종합 판정 생성."""
import json, os, sys, re

sys.path.insert(0, ".")

stages = ["iac", "sast", "sca", "image", "dast"]
stage_details = []

for stage in stages:
    path = f"scan-results/{stage}-llm-gate/{stage}-llm-gate.json"
    if not os.path.exists(path):
        continue
    gate = json.load(open(path))
    decision = gate.get("decision", "unknown")
    matching = gate.get("matching", {})
    matched = len(matching.get("matched_pairs_sample", []))
    unmatched = len(gate.get("unmatched_findings", []))
    summary = gate.get("llm_analysis", {}).get("summary", "")
    stage_details.append(
        f"[{stage.upper()}] gate={decision}, 동시탐지={matched}건, 단독탐지={unmatched}건"
        + f"\n  요약: {summary[:150]}"
    )

if not stage_details:
    print("No gate files found, skipping verdict")
    sys.exit(0)

has_fail = any("gate=fail" in s for s in stage_details)
final_decision = "BLOCK (배포 차단)" if has_fail else "ALLOW (배포 허용)"

print(f"종합 판정 대상: {len(stage_details)}개 stage, 최종: {final_decision}")

prompt = (
    "너는 DevSecOps 보안 파이프라인의 최종 판정을 내리는 전문가다.\n"
    "아래는 각 보안 검사 단계의 분석 결과이다. 이를 종합하여 최종 판정을 한국어로 작성하라.\n\n"
    + "\n".join(stage_details) + "\n\n"
    + "★★★ 최종 게이트 판정 결과: " + final_decision + " ★★★\n\n"
    + "위 최종 판정 결과를 반드시 반영하여 작성하라.\n"
    + "ALLOW인 경우: 배포가 승인된 이유, 발견된 취약점이 임계값 이내인 점, 보안 상태가 양호한 점을 긍정적 톤으로 서술하라.\n"
    + "BLOCK인 경우: 배포가 차단된 이유, 어떤 단계에서 임계값을 초과했는지, 즉시 조치 항목을 서술하라.\n\n"
    + "다음을 포함하여 작성하라:\n"
    + "1. 최종 판정 결과와 그 이유\n"
    + "2. 각 단계별 주요 발견사항 요약\n"
    + "3. 전체적인 보안 상태 평가\n\n"
    + "아래 JSON 형식으로만 응답하라:\n"
    + '{"verdict": "5~8문장의 상세한 종합 판정 (한국어)"}'
)

from engine.llm.client import call_llm

resp = call_llm(prompt)
match = re.search(r"\{[\s\S]+\}", resp)
if match:
    verdict_data = json.loads(match.group(0))
    print("종합 판정 생성 완료")
    print(f"  verdict: {verdict_data.get('verdict', '')[:100]}...")
else:
    verdict_data = {"verdict": "종합 판정 생성 실패", "priority_actions": []}
    print("LLM 응답 파싱 실패")

import urllib.request

backend = os.environ.get("BACKEND_URL", "") or os.environ.get("API_SERVER_URL", "")
backend = backend.rstrip("/")
if backend and not backend.endswith("/api/v1"):
    backend = f"{backend}/api/v1"
upload_key = os.environ.get("SECUREFLOW_UPLOAD_KEY", "")
commit = os.environ.get("COMMIT_SHA", "")
if not backend:
    print("BACKEND_URL/API_SERVER_URL 미설정, overall verdict 업로드 스킵")
    sys.exit(0)
payload = json.dumps({
    "stage": "overall-verdict",
    "commit_hash": commit,
    "gate_result": {
        "type": "overall_verdict",
        "summaries": {"_overall": verdict_data},
    },
}).encode("utf-8")
req = urllib.request.Request(
    f"{backend}/scans/gate-result",
    data=payload,
    headers={
        "Content-Type": "application/json",
        **({"X-SecureFlow-Upload-Key": upload_key} if upload_key else {}),
    },
)
try:
    r = urllib.request.urlopen(req, timeout=30)
    print(f"EC2 전송 완료: {r.read().decode()}")
except Exception as e:
    print(f"EC2 전송 실패: {e}")
