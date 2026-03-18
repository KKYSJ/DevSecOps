"""
LLM 교차 검증 프롬프트를 생성합니다.
각 카테고리(SAST, SCA, IaC, DAST)에 맞는 한국어 프롬프트를 빌드합니다.
"""

import json
import logging

logger = logging.getLogger(__name__)

# 카테고리별 도구 이름 매핑
_TOOL_NAMES = {
    "SAST": ("SonarQube", "Semgrep"),
    "SCA": ("Trivy", "Dependency-Check"),
    "IaC": ("tfsec", "Checkov"),
    "DAST": ("OWASP ZAP", None),
}

# 카테고리별 대상 레이블 이름
_TARGET_LABEL_NAMES = {
    "SAST": "코드 위치",
    "SCA": "의존성 패키지",
    "IaC": "IaC 리소스",
    "DAST": "엔드포인트",
}


def _format_finding(finding: dict | None, category: str) -> str:
    """finding을 프롬프트용 텍스트로 포맷합니다."""
    if finding is None:
        return "탐지 안 됨"

    parts = []
    parts.append(f"  - 심각도: {finding.get('severity', 'UNKNOWN')}")
    parts.append(f"  - 제목: {finding.get('title', '')}")

    if finding.get("rule_id"):
        parts.append(f"  - 규칙 ID: {finding['rule_id']}")

    if category == "SAST":
        if finding.get("file_path"):
            parts.append(f"  - 파일: {finding['file_path']}")
        if finding.get("line_number"):
            parts.append(f"  - 라인: {finding['line_number']}")
        if finding.get("cwe_id"):
            parts.append(f"  - CWE: {finding['cwe_id']}")

    elif category == "SCA":
        if finding.get("package_name"):
            parts.append(f"  - 패키지: {finding['package_name']}")
        if finding.get("package_version"):
            parts.append(f"  - 버전: {finding['package_version']}")
        if finding.get("cve_id"):
            parts.append(f"  - CVE: {finding['cve_id']}")
        if finding.get("fixed_version"):
            parts.append(f"  - 수정 버전: {finding['fixed_version']}")

    elif category == "IaC":
        if finding.get("file_path"):
            parts.append(f"  - 파일: {finding['file_path']}")
        if finding.get("line_number"):
            parts.append(f"  - 라인: {finding['line_number']}")
        if finding.get("_resource"):
            parts.append(f"  - 리소스: {finding['_resource']}")

    elif category == "DAST":
        if finding.get("url"):
            parts.append(f"  - URL: {finding['url']}")
        if finding.get("http_method"):
            parts.append(f"  - HTTP 메서드: {finding['http_method']}")
        if finding.get("parameter"):
            parts.append(f"  - 파라미터: {finding['parameter']}")

    if finding.get("description"):
        desc = finding["description"]
        if len(desc) > 200:
            desc = desc[:200] + "..."
        parts.append(f"  - 설명: {desc}")

    return "\n".join(parts)


def _format_pair(idx: int, pair: dict, category: str) -> str:
    """단일 matched_pair를 프롬프트용 텍스트로 포맷합니다."""
    tool_a_name, tool_b_name = _TOOL_NAMES.get(category, ("도구A", "도구B"))
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")
    severity = pair.get("severity", "UNKNOWN")
    corr_key = pair.get("correlation_key", "")

    lines = [
        f"### 쌍 {idx + 1}",
        f"- correlation_key: {corr_key}",
        f"- 최고 심각도: {severity}",
        f"",
        f"**{tool_a_name} 탐지 결과:**",
        _format_finding(finding_a, category),
        f"",
    ]

    if tool_b_name:
        lines.extend([
            f"**{tool_b_name} 탐지 결과:**",
            _format_finding(finding_b, category),
            f"",
        ])

    return "\n".join(lines)


def build_cross_validation_prompt(category: str, matched_pairs: list[dict]) -> str:
    """LLM 교차 검증 프롬프트를 생성합니다.

    Args:
        category: 카테고리 ("SAST", "SCA", "IaC", "DAST")
        matched_pairs: 해당 카테고리의 matched_pair 목록

    Returns:
        LLM에 전송할 한국어 프롬프트 문자열
    """
    tool_a_name, tool_b_name = _TOOL_NAMES.get(category, ("도구A", "도구B"))
    target_label = _TARGET_LABEL_NAMES.get(category, "대상")

    if category == "DAST":
        header = f"""너는 보안 취약점 분석 전문가다.

아래는 {tool_a_name}이 탐지한 {category} 보안 취약점 목록이다.
DAST는 단독 도구이므로 교차 검증이 아닌 단일 판정을 수행한다.

각 finding에 대해 다음 기준으로 판정하라:
- TRUE_POSITIVE: 증거, 위치, 취약점 성격이 명확하게 확인된 경우
- REVIEW_NEEDED: 추가 확인이 필요한 경우
- FALSE_POSITIVE: 명백히 오탐인 경우

"""
    else:
        header = f"""너는 보안 취약점 교차 검증 전문가다.

아래는 {tool_a_name}과 {tool_b_name}이 탐지한 {category} 보안 취약점 쌍 목록이다.
각 쌍에 대해 다음 기준으로 판정하라:

- TRUE_POSITIVE: 두 도구가 동일한 {target_label}에서 같은 성격의 취약점을 탐지한 경우
- REVIEW_NEEDED: 한 도구만 탐지했거나 동일 취약점으로 단정하기 어려운 경우
- FALSE_POSITIVE: 명백히 오탐인 경우 (두 도구 모두 오탐이거나 근거가 없는 경우)

"""

    pairs_text = "\n".join(
        _format_pair(idx, pair, category)
        for idx, pair in enumerate(matched_pairs)
    )

    output_schema = _build_output_schema(matched_pairs, category)

    footer = f"""
---

위 각 쌍에 대해 아래 JSON 형식으로만 응답하라. 설명 없이 JSON만 반환하라.
모든 텍스트 필드(reason, action_text, title_ko, description_ko)는 반드시 한국어로 작성하라.

{json.dumps(output_schema, ensure_ascii=False, indent=2)}
"""

    return header + pairs_text + footer


def _build_output_schema(matched_pairs: list[dict], category: str) -> dict:
    """LLM 출력 스키마를 생성합니다."""
    judgements = []
    for idx, pair in enumerate(matched_pairs):
        judgements.append({
            "pair_index": idx,
            "correlation_key": pair.get("correlation_key", ""),
            "judgement_code": "TRUE_POSITIVE | REVIEW_NEEDED | FALSE_POSITIVE",
            "confidence_level": "HIGH | MED | LOW",
            "reason": "한국어로 판정 근거 작성 (2~4문장)",
            "action_text": "한국어로 권장 조치 작성",
            "title_ko": "취약점 제목을 한국어로 번역",
            "description_ko": "취약점 설명을 한국어로 번역 (2~3문장 요약)",
        })

    return {
        "category": category,
        "judgements": judgements,
    }


def parse_llm_response(response_text: str, matched_pairs: list[dict]) -> list[dict]:
    """LLM 응답을 파싱하여 matched_pair에 판정 결과를 적용합니다.

    Args:
        response_text: LLM 응답 텍스트
        matched_pairs: 원본 matched_pair 목록

    Returns:
        judgement_code, reason, action_text가 추가된 matched_pair 목록
    """
    import re

    try:
        # JSON 코드 블록 추출 시도
        json_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", response_text)
        if json_match:
            json_str = json_match.group(1)
        else:
            # 중괄호로 시작하는 JSON 직접 추출
            json_match = re.search(r'\{[\s\S]+\}', response_text)
            if json_match:
                json_str = json_match.group(0)
            else:
                logger.warning("LLM 응답에서 JSON을 찾을 수 없음, 규칙 기반 판정 사용")
                return matched_pairs

        data = json.loads(json_str)
        judgements = data.get("judgements", [])

        # 인덱스 기반으로 매핑
        result_pairs = list(matched_pairs)
        for judgement in judgements:
            idx = judgement.get("pair_index")
            if idx is None or idx >= len(result_pairs):
                continue

            pair = dict(result_pairs[idx])
            jcode = judgement.get("judgement_code", "REVIEW_NEEDED")
            if jcode not in ("TRUE_POSITIVE", "REVIEW_NEEDED", "FALSE_POSITIVE"):
                jcode = "REVIEW_NEEDED"

            pair["judgement_code"] = jcode
            pair["confidence_level"] = judgement.get("confidence_level", "MED")
            pair["reason"] = judgement.get("reason", "")
            pair["action_text"] = judgement.get("action_text", "")
            pair["title_ko"] = judgement.get("title_ko", "")
            pair["description_ko"] = judgement.get("description_ko", "")
            result_pairs[idx] = pair

        return result_pairs

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("LLM 응답 파싱 실패 (%s), 규칙 기반 판정 사용", e)
        return _rule_based_fallback(matched_pairs)


def _rule_based_fallback(matched_pairs: list[dict]) -> list[dict]:
    """LLM 파싱 실패 시 규칙 기반으로 judgement_code와 한국어 reason을 채웁니다."""
    result = []
    for pair in matched_pairs:
        p = dict(pair)
        fa = p.get("finding_a")
        fb = p.get("finding_b")
        sev = p.get("severity", "MEDIUM")

        if fa and fb:
            p["judgement_code"] = "TRUE_POSITIVE"
            p["confidence_level"] = "HIGH"
            p["reason"] = f"두 도구 모두 동일한 위치에서 {sev} 수준의 취약점을 탐지했습니다. 실제 취약점일 가능성이 높습니다."
            p["action_text"] = "즉시 코드를 검토하고 수정하세요."
        elif fa or fb:
            found = fa or fb
            tool = found.get("tool", "도구")
            p["judgement_code"] = "REVIEW_NEEDED"
            p["confidence_level"] = "MED"
            p["reason"] = f"{tool}만 탐지한 항목입니다. 다른 도구에서는 미탐지되어 추가 확인이 필요합니다."
            p["action_text"] = "수동으로 해당 코드/패키지를 검토하세요."
        else:
            p["judgement_code"] = "FALSE_POSITIVE"
            p["confidence_level"] = "LOW"
            p["reason"] = "두 도구 모두 탐지하지 않았습니다."
            p["action_text"] = "조치 불필요."
        result.append(p)
    return result
