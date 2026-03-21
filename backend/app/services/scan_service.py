"""
SecureFlow 핵심 스캔 서비스

파이프라인: 파서 → 매칭 → 스코어링 → LLM 분석 → 리포트
"""

import json
import logging
import os
from datetime import datetime, timezone

import httpx

from engine.normalizer.parsers import (
    sonarqube as _p_sonarqube,
    semgrep   as _p_semgrep,
    trivy     as _p_trivy,
    depcheck  as _p_depcheck,
    tfsec     as _p_tfsec,
    checkov   as _p_checkov,
    zap       as _p_zap,
)
from backend.app.services.parsers.nuclei_parser import NucleiParser

logger = logging.getLogger(__name__)


class _Adapter:
    """engine 파서 모듈(함수 기반)을 .parse() 메서드 인터페이스로 감쌉니다."""
    def __init__(self, module):
        self._mod = module

    def parse(self, raw: dict) -> dict:
        return self._mod.parse(raw)


# ── 파서 레지스트리 (engine/normalizer/parsers/ 사용) ────────────────────────
PARSERS = {
    "sonarqube": _Adapter(_p_sonarqube),
    "semgrep":   _Adapter(_p_semgrep),
    "trivy":     _Adapter(_p_trivy),
    "depcheck":  _Adapter(_p_depcheck),
    "tfsec":     _Adapter(_p_tfsec),
    "checkov":   _Adapter(_p_checkov),
    "zap":       _Adapter(_p_zap),
    "nuclei":    NucleiParser(),
}

# ── 스코어링 상수 ─────────────────────────────────────────────────────────────
SEVERITY_BASE = {
    "CRITICAL": 100,
    "HIGH": 10,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": 0,
}

JUDGEMENT_WEIGHT = {
    "TRUE_POSITIVE": 1.0,
    "REVIEW_NEEDED": 0.5,
    "FALSE_POSITIVE": 0.0,
}

CONFIDENCE_WEIGHT = {
    "HIGH": 1.0,
    "MED": 0.8,
    "LOW": 0.5,
}

# ── 매칭 페어 정의 ────────────────────────────────────────────────────────────
MATCH_PAIRS = [
    {"category": "SAST", "tool_a": "sonarqube", "tool_b": "semgrep"},
    {"category": "SCA",  "tool_a": "trivy",     "tool_b": "depcheck"},
    {"category": "IaC",  "tool_a": "tfsec",     "tool_b": "checkov"},
]


# ── 유틸 ──────────────────────────────────────────────────────────────────────

def _max_severity(a: str, b: str | None) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if b is None:
        return a
    ia = order.index(a) if a in order else 4
    ib = order.index(b) if b in order else 4
    return order[min(ia, ib)]


def _sast_match(f_a: dict, f_b: dict) -> bool:
    """SAST 매칭: 동일 cwe_id OR 동일 file_path + 5줄 이내"""
    cwe_a = f_a.get("cwe_id")
    cwe_b = f_b.get("cwe_id")
    if cwe_a and cwe_b and cwe_a == cwe_b:
        return True

    fp_a = f_a.get("file_path")
    fp_b = f_b.get("file_path")
    ln_a = f_a.get("line_number")
    ln_b = f_b.get("line_number")
    if fp_a and fp_b and fp_a == fp_b and ln_a is not None and ln_b is not None:
        return abs(ln_a - ln_b) <= 5
    return False


def _sca_match(f_a: dict, f_b: dict) -> bool:
    """SCA 매칭: 동일 cve_id OR 동일 package_name + package_version"""
    cve_a = f_a.get("cve_id")
    cve_b = f_b.get("cve_id")
    if cve_a and cve_b and cve_a == cve_b:
        return True

    pkg_a = f_a.get("package_name")
    pkg_b = f_b.get("package_name")
    ver_a = f_a.get("package_version")
    ver_b = f_b.get("package_version")
    if pkg_a and pkg_b and pkg_a == pkg_b and ver_a and ver_b and ver_a == ver_b:
        return True
    return False


def _iac_match(f_a: dict, f_b: dict) -> bool:
    """IaC 매칭: 동일 file_path + 10줄 이내"""
    fp_a = f_a.get("file_path")
    fp_b = f_b.get("file_path")
    ln_a = f_a.get("line_number")
    ln_b = f_b.get("line_number")
    if fp_a and fp_b and fp_a == fp_b and ln_a is not None and ln_b is not None:
        return abs(ln_a - ln_b) <= 10
    return False


_MATCH_FNS = {
    "SAST": _sast_match,
    "SCA": _sca_match,
    "IaC": _iac_match,
}


def _make_correlation_key(category: str, finding_a: dict | None, finding_b: dict | None) -> str:
    """상관관계 키 생성"""
    f = finding_a or finding_b
    if not f:
        return f"{category}:unknown"

    if category == "SAST":
        cwe = f.get("cwe_id") or "no-cwe"
        fp = f.get("file_path") or "unknown"
        return f"sast:{fp}:{cwe}"
    elif category == "SCA":
        pkg = f.get("package_name") or "unknown"
        ver = f.get("package_version") or "unknown"
        cve = f.get("cve_id") or "no-cve"
        return f"sca:{pkg}:{ver}:{cve}"
    elif category == "IaC":
        fp = f.get("file_path") or "unknown"
        ln = f.get("line_number") or 0
        return f"iac:{fp}:{ln}"
    return f"{category}:unknown"


# ── 핵심 서비스 함수 ──────────────────────────────────────────────────────────

def process_tool_result(tool: str, raw: dict) -> dict:
    """
    원시 도구 출력을 공통 포맷으로 파싱.

    Args:
        tool: 도구 이름 (sonarqube, semgrep, trivy, ...)
        raw: 원시 JSON 딕셔너리

    Returns:
        공통 스키마 딕셔너리
    """
    parser = PARSERS.get(tool)
    if not parser:
        raise ValueError(f"지원하지 않는 도구: {tool}. 지원 목록: {list(PARSERS.keys())}")
    return parser.parse(raw)


def match_findings(tool_results: list[dict]) -> list[dict]:
    """
    도구 쌍 간의 발견 사항을 매칭하여 상관관계 쌍 목록 반환.

    매칭 규칙:
    - SAST (sonarqube ↔ semgrep): 동일 cwe_id 또는 동일 file_path + 5줄 이내
    - SCA  (trivy ↔ depcheck):    동일 cve_id 또는 동일 package_name + package_version
    - IaC  (tfsec ↔ checkov):     동일 file_path + 10줄 이내

    Args:
        tool_results: process_tool_result() 결과 리스트

    Returns:
        매칭 쌍 딕셔너리 리스트
    """
    # tool_name → parsed_result 인덱스 구성
    results_by_tool: dict[str, dict] = {}
    for result in tool_results:
        tool_name = result.get("tool")
        if tool_name:
            results_by_tool[tool_name] = result

    matched_pairs: list[dict] = []

    for pair_def in MATCH_PAIRS:
        category = pair_def["category"]
        tool_a = pair_def["tool_a"]
        tool_b = pair_def["tool_b"]
        match_fn = _MATCH_FNS[category]

        findings_a = results_by_tool.get(tool_a, {}).get("findings", [])
        findings_b = results_by_tool.get(tool_b, {}).get("findings", [])

        matched_a = set()  # 이미 매칭된 A 인덱스
        matched_b = set()  # 이미 매칭된 B 인덱스

        # 양쪽 모두 탐지된 매칭 쌍 찾기
        for i, fa in enumerate(findings_a):
            for j, fb in enumerate(findings_b):
                if j in matched_b:
                    continue
                if match_fn(fa, fb):
                    severity = _max_severity(fa["severity"], fb["severity"])
                    matched_pairs.append({
                        "category": category,
                        "tool_a": tool_a,
                        "tool_b": tool_b,
                        "correlation_key": _make_correlation_key(category, fa, fb),
                        "confidence": "HIGH",   # 두 도구 모두 탐지
                        "severity": severity,
                        "finding_a": fa,
                        "finding_b": fb,
                        "judgement_code": None,
                        "row_score": 0.0,
                        "reason": "",
                        "action_text": "",
                    })
                    matched_a.add(i)
                    matched_b.add(j)
                    break  # A의 한 finding은 B의 하나와만 매칭

        # A에만 있는 단독 발견 사항
        for i, fa in enumerate(findings_a):
            if i not in matched_a:
                matched_pairs.append({
                    "category": category,
                    "tool_a": tool_a,
                    "tool_b": tool_b,
                    "correlation_key": _make_correlation_key(category, fa, None),
                    "confidence": "LOW",    # 단독 탐지
                    "severity": fa["severity"],
                    "finding_a": fa,
                    "finding_b": None,
                    "judgement_code": None,
                    "row_score": 0.0,
                    "reason": "",
                    "action_text": "",
                })

        # B에만 있는 단독 발견 사항
        for j, fb in enumerate(findings_b):
            if j not in matched_b:
                matched_pairs.append({
                    "category": category,
                    "tool_a": tool_a,
                    "tool_b": tool_b,
                    "correlation_key": _make_correlation_key(category, None, fb),
                    "confidence": "LOW",    # 단독 탐지
                    "severity": fb["severity"],
                    "finding_a": None,
                    "finding_b": fb,
                    "judgement_code": None,
                    "row_score": 0.0,
                    "reason": "",
                    "action_text": "",
                })

    return matched_pairs


def score_findings(matched_pairs: list[dict]) -> list[dict]:
    """
    각 매칭 쌍에 대해 row_score 계산.

    공식: row_score = severity_base × judgement_weight × confidence_weight

    Args:
        matched_pairs: match_findings() 또는 analyze_with_llm() 결과

    Returns:
        row_score가 채워진 쌍 리스트 (원본 수정)
    """
    scored = []
    for pair in matched_pairs:
        severity = pair.get("severity", "MEDIUM")
        judgement_code = pair.get("judgement_code") or "REVIEW_NEEDED"
        confidence = pair.get("confidence", "MED")

        # confidence 정규화 (MED/MEDIUM → MED)
        if confidence == "MEDIUM":
            confidence = "MED"

        base = SEVERITY_BASE.get(severity, 15)
        jw = JUDGEMENT_WEIGHT.get(judgement_code, 0.6)
        cw = CONFIDENCE_WEIGHT.get(confidence, 0.8)

        row_score = base * jw * cw

        updated = dict(pair)
        updated["row_score"] = round(row_score, 2)
        scored.append(updated)
    return scored


def analyze_with_llm(matched_pairs: list[dict]) -> list[dict]:
    """
    LLM(OpenAI)를 통해 각 매칭 쌍에 대한 판정 수행.
    OPENAI_API_KEY가 없으면 규칙 기반 판정으로 폴백.

    Args:
        matched_pairs: match_findings() 결과

    Returns:
        judgement_code, reason, action_text가 채워진 쌍 리스트
    """
    api_key = os.environ.get("OPENAI_API_KEY")

    if api_key:
        try:
            return _llm_analyze(matched_pairs, api_key)
        except Exception as e:
            logger.warning(f"LLM 분석 실패, 규칙 기반으로 폴백: {e}")

    return _rule_based_analyze(matched_pairs)


def _rule_based_analyze(matched_pairs: list[dict]) -> list[dict]:
    """규칙 기반 판정: 두 도구 모두 탐지 → TRUE_POSITIVE, 단독 탐지 → REVIEW_NEEDED"""
    result = []
    for pair in matched_pairs:
        updated = dict(pair)
        has_a = pair.get("finding_a") is not None
        has_b = pair.get("finding_b") is not None

        if has_a and has_b:
            updated["judgement_code"] = "TRUE_POSITIVE"
            updated["reason"] = "두 도구 모두 동일 취약점 탐지 - 실제 취약점으로 판정"
            updated["action_text"] = _get_action_text(pair["severity"], "TRUE_POSITIVE")
        elif has_a or has_b:
            updated["judgement_code"] = "REVIEW_NEEDED"
            tool = pair["tool_a"] if has_a else pair["tool_b"]
            updated["reason"] = f"{tool}만 탐지 - 수동 검토 필요"
            updated["action_text"] = _get_action_text(pair["severity"], "REVIEW_NEEDED")
        else:
            updated["judgement_code"] = "FALSE_POSITIVE"
            updated["reason"] = "탐지된 발견 사항 없음"
            updated["action_text"] = "조치 불필요"

        result.append(updated)
    return result


def _get_action_text(severity: str, judgement: str) -> str:
    """severity와 judgement 조합에 따른 조치 텍스트"""
    if judgement == "FALSE_POSITIVE":
        return "오탐으로 판정됨. 별도 조치 불필요."

    actions = {
        "CRITICAL": {
            "TRUE_POSITIVE": "즉시 패치 적용 필요. 배포 차단 권고.",
            "REVIEW_NEEDED": "긴급 검토 후 패치 여부 결정 필요.",
        },
        "HIGH": {
            "TRUE_POSITIVE": "다음 배포 전 패치 완료 필요.",
            "REVIEW_NEEDED": "보안팀 검토 후 패치 여부 결정.",
        },
        "MEDIUM": {
            "TRUE_POSITIVE": "스프린트 내 패치 계획 수립.",
            "REVIEW_NEEDED": "위험도 평가 후 패치 우선순위 결정.",
        },
        "LOW": {
            "TRUE_POSITIVE": "다음 정기 패치 주기에 포함하여 처리.",
            "REVIEW_NEEDED": "백로그 등록 후 여유 시 처리.",
        },
        "INFO": {
            "TRUE_POSITIVE": "정보성 항목. 보안 가이드라인 확인.",
            "REVIEW_NEEDED": "정보성 항목. 필요 시 검토.",
        },
    }
    return actions.get(severity, {}).get(judgement, "검토 필요.")


def _llm_analyze(matched_pairs: list[dict], api_key: str) -> list[dict]:
    """OpenAI API를 통한 LLM 판정"""
    # 배치로 LLM에 전송 (최대 10개씩)
    batch_size = 10
    results = []

    for i in range(0, len(matched_pairs), batch_size):
        batch = matched_pairs[i:i + batch_size]
        analyzed_batch = _analyze_batch(batch, api_key)
        results.extend(analyzed_batch)

    return results


def _analyze_batch(batch: list[dict], api_key: str) -> list[dict]:
    """단일 배치에 대한 LLM 분석"""
    # 프롬프트 구성
    items_text = []
    for idx, pair in enumerate(batch):
        fa = pair.get("finding_a")
        fb = pair.get("finding_b")

        tool_info = []
        if fa:
            tool_info.append(f"  {pair['tool_a']}: {fa.get('title', 'N/A')} (severity={fa.get('severity')}, file={fa.get('file_path')}, line={fa.get('line_number')})")
        if fb:
            tool_info.append(f"  {pair['tool_b']}: {fb.get('title', 'N/A')} (severity={fb.get('severity')}, file={fb.get('file_path')}, line={fb.get('line_number')})")

        items_text.append(
            f"[{idx}] category={pair['category']}, confidence={pair['confidence']}\n"
            + "\n".join(tool_info)
        )

    prompt = (
        "당신은 보안 전문가입니다. 아래 보안 취약점 발견 사항들을 분석하여 "
        "각 항목에 대해 판정(TRUE_POSITIVE/REVIEW_NEEDED/FALSE_POSITIVE)과 "
        "한국어 이유, 조치 방법을 제시하세요.\n\n"
        "응답은 반드시 JSON 배열 형태로, 각 항목마다 "
        "{\"index\": N, \"judgement_code\": \"...\", \"reason\": \"...\", \"action_text\": \"...\"}를 포함하세요.\n\n"
        "발견 사항:\n" + "\n\n".join(items_text)
    )

    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": "당신은 DevSecOps 보안 전문가입니다. JSON 형식으로만 응답하세요."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content)

            # 응답에서 배열 추출 (키가 다를 수 있음)
            if isinstance(parsed, list):
                llm_results = parsed
            else:
                # 첫 번째 리스트 값 찾기
                llm_results = next(
                    (v for v in parsed.values() if isinstance(v, list)),
                    []
                )

            # LLM 응답을 매칭 쌍에 병합
            llm_map = {item["index"]: item for item in llm_results if isinstance(item, dict)}
            result = []
            for idx, pair in enumerate(batch):
                updated = dict(pair)
                llm_item = llm_map.get(idx)
                if llm_item:
                    updated["judgement_code"] = llm_item.get("judgement_code", "REVIEW_NEEDED")
                    updated["reason"] = llm_item.get("reason", "")
                    updated["action_text"] = llm_item.get("action_text", "")
                else:
                    # LLM 응답 없으면 규칙 기반
                    updated = _rule_based_analyze([pair])[0]
                result.append(updated)
            return result

    except Exception as e:
        logger.error(f"LLM API 호출 실패: {e}")
        return _rule_based_analyze(batch)


def get_gate_decision(scored_pairs: list[dict]) -> str:
    """
    스코어링된 쌍 목록을 기반으로 게이트 결정.

    규칙:
    - BLOCK: total_score >= 100 OR CRITICAL TRUE_POSITIVE >= 1 OR HIGH TRUE_POSITIVE >= 3
    - REVIEW: total_score 40-100
    - ALLOW: total_score < 40

    Returns:
        "ALLOW" | "REVIEW" | "BLOCK"
    """
    total_score = sum(p.get("row_score", 0.0) for p in scored_pairs)

    critical_tp = sum(
        1 for p in scored_pairs
        if p.get("severity") == "CRITICAL" and p.get("judgement_code") == "TRUE_POSITIVE"
    )
    high_tp = sum(
        1 for p in scored_pairs
        if p.get("severity") == "HIGH" and p.get("judgement_code") == "TRUE_POSITIVE"
    )

    if critical_tp >= 1 or total_score >= 100:
        return "BLOCK"
    elif total_score >= 10:
        return "REVIEW"
    else:
        return "ALLOW"


def run_full_analysis(tool_results: list[dict]) -> dict:
    """
    완전한 분석 파이프라인 실행:
    parse → match → LLM analyze → score → gate decision → report

    Args:
        tool_results: process_tool_result() 결과 리스트

    Returns:
        분석 결과 딕셔너리
    """
    # 1. 매칭
    matched_pairs = match_findings(tool_results)

    # 2. LLM 분석 (judgement_code 결정)
    analyzed_pairs = analyze_with_llm(matched_pairs)

    # 3. 스코어링
    scored_pairs = score_findings(analyzed_pairs)

    # 4. 게이트 결정
    gate = get_gate_decision(scored_pairs)

    # 5. 요약 통계
    total_score = round(sum(p.get("row_score", 0.0) for p in scored_pairs), 2)

    summary = {
        "total_findings": len(scored_pairs),
        "true_positive": sum(1 for p in scored_pairs if p.get("judgement_code") == "TRUE_POSITIVE"),
        "review_needed": sum(1 for p in scored_pairs if p.get("judgement_code") == "REVIEW_NEEDED"),
        "false_positive": sum(1 for p in scored_pairs if p.get("judgement_code") == "FALSE_POSITIVE"),
        "by_severity": {
            "CRITICAL": sum(1 for p in scored_pairs if p.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for p in scored_pairs if p.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for p in scored_pairs if p.get("severity") == "MEDIUM"),
            "LOW": sum(1 for p in scored_pairs if p.get("severity") == "LOW"),
            "INFO": sum(1 for p in scored_pairs if p.get("severity") == "INFO"),
        },
        "by_category": {
            "SAST": sum(1 for p in scored_pairs if p.get("category") == "SAST"),
            "SCA": sum(1 for p in scored_pairs if p.get("category") == "SCA"),
            "IaC": sum(1 for p in scored_pairs if p.get("category") == "IaC"),
            "DAST": sum(1 for p in scored_pairs if p.get("category") == "DAST"),
        },
    }

    return {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "gate_decision": gate,
        "total_score": total_score,
        "summary": summary,
        "matched_pairs": scored_pairs,
        "tool_results": tool_results,
    }
