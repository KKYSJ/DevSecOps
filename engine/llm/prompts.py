"""
LLM 교차 검증 프롬프트를 생성합니다.
각 카테고리(SAST, SCA, IaC, DAST)에 맞는 한국어 프롬프트를 빌드합니다.

핵심 역할:
1. 공통 결과 비교 → 두 도구가 같은 취약점을 잡았으면 신뢰도 높음
2. 상이 결과 분석 → 한쪽만 잡았으면 오탐/미탐 판단
3. 위험도 재평가 → 실제 코드 맥락에서 심각도 재평가
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


def _format_finding_compact(finding: dict | None, category: str) -> str:
    """finding을 간결하게 포맷합니다."""
    if finding is None:
        return "미탐지"

    parts = []
    parts.append(f"심각도={finding.get('severity', '?')}")

    if finding.get("title"):
        title = finding["title"]
        if len(title) > 80:
            title = title[:80] + "..."
        parts.append(f"제목=\"{title}\"")

    if category == "SAST":
        if finding.get("file_path"):
            parts.append(f"파일={finding['file_path']}")
        if finding.get("cwe_id"):
            parts.append(f"CWE={finding['cwe_id']}")
    elif category == "SCA":
        if finding.get("package_name"):
            pkg = finding["package_name"]
            ver = finding.get("package_version", "")
            parts.append(f"패키지={pkg}@{ver}")
        if finding.get("cve_id"):
            parts.append(f"CVE={finding['cve_id']}")
        if finding.get("fixed_version"):
            parts.append(f"수정버전={finding['fixed_version']}")
    elif category == "IaC":
        if finding.get("file_path"):
            parts.append(f"파일={finding['file_path']}")
    elif category == "DAST":
        if finding.get("url"):
            parts.append(f"URL={finding['url']}")

    return " | ".join(parts)


def _format_pair_compact(idx: int, pair: dict, category: str) -> str:
    """단일 matched_pair를 간결하게 포맷합니다."""
    tool_a_name, tool_b_name = _TOOL_NAMES.get(category, ("도구A", "도구B"))
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")

    # 탐지 상태 판별
    if finding_a and finding_b:
        match_type = "동시탐지"
    elif finding_a:
        match_type = f"{tool_a_name}만 탐지"
    elif finding_b:
        match_type = f"{tool_b_name}만 탐지"
    else:
        match_type = "미탐지"

    lines = [f"[{idx + 1}] {match_type} | 심각도={pair.get('severity', '?')}"]
    lines.append(f"  {tool_a_name}: {_format_finding_compact(finding_a, category)}")
    if tool_b_name:
        lines.append(f"  {tool_b_name}: {_format_finding_compact(finding_b, category)}")

    return "\n".join(lines)


def build_cross_validation_prompt(category: str, matched_pairs: list[dict]) -> str:
    """LLM 교차 검증 프롬프트를 생성합니다."""
    tool_a_name, tool_b_name = _TOOL_NAMES.get(category, ("도구A", "도구B"))

    if category == "DAST":
        header = f"""너는 DevSecOps 보안 분석 전문가다. 비개발자도 이해할 수 있도록 한국어로 분석해라.

{tool_a_name}이 탐지한 DAST 취약점을 분석한다.

"""
    else:
        header = f"""너는 DevSecOps 보안 분석 전문가다. 비개발자도 이해할 수 있도록 한국어로 분석해라.

{tool_a_name}과 {tool_b_name}의 {category} 스캔 결과를 교차 검증한다.

분석 기준:
1. 공통 결과 비교: 두 도구가 같은 취약점을 탐지했으면 실제 취약점(TRUE_POSITIVE)
2. 상이 결과 분석: 한쪽만 탐지했으면 오탐 가능성 검토(REVIEW_NEEDED) 또는 오탐(FALSE_POSITIVE)
3. 위험도 재평가: 도구가 준 심각도가 실제 맥락에서 적절한지 재평가

"""

    pairs_text = "\n".join(
        _format_pair_compact(idx, pair, category)
        for idx, pair in enumerate(matched_pairs)
    )

    output_schema = _build_output_schema(matched_pairs, category)

    footer = f"""

---
위 항목 각각에 대해 아래 JSON 형식으로만 응답하라. JSON 외 텍스트 금지.

중요: 모든 텍스트를 반드시 한국어로 작성하라.
- title_ko: 기술 용어를 포함하되, 비개발자도 이해할 수 있는 한국어 제목 (예: "SQL 인젝션 - 사용자 입력이 데이터베이스 쿼리에 직접 삽입됨")
- risk_summary: 이 취약점이 악용되면 어떤 피해가 발생하는지 한국어로 1~2문장 (예: "공격자가 데이터베이스의 모든 사용자 정보를 탈취할 수 있습니다")
- reason: 왜 이 판정을 내렸는지 근거를 한국어로 2~3문장
- action_text: 구체적인 수정 방법을 한국어로 (예: "cursor.execute()에 파라미터 바인딩을 사용하세요")
- reassessed_severity: 실제 맥락에서 재평가한 심각도 (CRITICAL/HIGH/MEDIUM/LOW)

{json.dumps(output_schema, ensure_ascii=False, indent=2)}
"""

    return header + pairs_text + footer


def _build_output_schema(matched_pairs: list[dict], category: str) -> dict:
    """LLM 출력 스키마를 생성합니다."""
    judgements = []
    for idx, pair in enumerate(matched_pairs):
        judgements.append({
            "pair_index": idx,
            "judgement_code": "TRUE_POSITIVE | REVIEW_NEEDED | FALSE_POSITIVE",
            "confidence_level": "HIGH | MED | LOW",
            "reassessed_severity": "CRITICAL | HIGH | MEDIUM | LOW",
            "title_ko": "한국어 취약점 제목",
            "risk_summary": "이 취약점이 악용되면 어떤 피해가 발생하는지 한국어로",
            "reason": "판정 근거를 한국어로 2~3문장",
            "action_text": "구체적 수정 방법을 한국어로",
        })

    return {
        "category": category,
        "judgements": judgements,
    }


def parse_llm_response(response_text: str, matched_pairs: list[dict]) -> list[dict]:
    """LLM 응답을 파싱하여 matched_pair에 판정 결과를 적용합니다."""
    import re

    try:
        # JSON 코드 블록 추출 시도
        json_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", response_text)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_match = re.search(r'\{[\s\S]+\}', response_text)
            if json_match:
                json_str = json_match.group(0)
            else:
                logger.warning("LLM 응답에서 JSON을 찾을 수 없음, 규칙 기반 판정 사용")
                return _rule_based_fallback(matched_pairs)

        data = json.loads(json_str)
        judgements = data.get("judgements", [])

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
            pair["risk_summary"] = judgement.get("risk_summary", "")
            pair["description_ko"] = judgement.get("risk_summary", "")
            pair["reassessed_severity"] = judgement.get("reassessed_severity", pair.get("severity", "MEDIUM"))
            result_pairs[idx] = pair

        return result_pairs

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("LLM 응답 파싱 실패 (%s), 규칙 기반 판정 사용", e)
        return _rule_based_fallback(matched_pairs)


def _rule_based_fallback(matched_pairs: list[dict]) -> list[dict]:
    """LLM 파싱 실패 시 규칙 기반으로 한국어 판정을 채웁니다."""
    result = []
    for pair in matched_pairs:
        p = dict(pair)
        fa = p.get("finding_a")
        fb = p.get("finding_b")
        sev = p.get("severity", "MEDIUM")
        title = (fa or fb or {}).get("title", "알 수 없는 취약점")
        if len(title) > 60:
            title = title[:60] + "..."

        if fa and fb:
            tool_a = fa.get("tool", "도구A")
            tool_b = fb.get("tool", "도구B")
            p["judgement_code"] = "TRUE_POSITIVE"
            p["confidence_level"] = "HIGH"
            p["title_ko"] = f"[확인됨] {title}"
            p["risk_summary"] = f"{tool_a}와 {tool_b} 두 도구가 동일한 위치에서 같은 취약점을 탐지했습니다. 실제 보안 위협일 가능성이 높습니다."
            p["reason"] = f"두 도구가 독립적으로 같은 취약점을 탐지하여 신뢰도가 높습니다. {sev} 수준으로 즉시 조치가 필요합니다."
            p["action_text"] = "해당 코드를 즉시 검토하고 보안 패치를 적용하세요."
            p["reassessed_severity"] = sev
        elif fa or fb:
            found = fa or fb
            tool = found.get("tool", "도구")
            p["judgement_code"] = "REVIEW_NEEDED"
            p["confidence_level"] = "MED"
            p["title_ko"] = f"[검토 필요] {title}"
            p["risk_summary"] = f"{tool}에서만 탐지된 항목입니다. 실제 취약점일 수 있으나 오탐 가능성도 있어 수동 확인이 필요합니다."
            p["reason"] = f"단일 도구({tool})만 탐지하여 교차 검증이 불가합니다. 오탐일 수 있으므로 보안 담당자의 수동 검토가 필요합니다."
            p["action_text"] = "보안 담당자가 직접 해당 코드/설정을 확인하세요."
            p["reassessed_severity"] = sev
        else:
            p["judgement_code"] = "FALSE_POSITIVE"
            p["confidence_level"] = "LOW"
            p["title_ko"] = "[오탐] 취약점 미확인"
            p["risk_summary"] = "두 도구 모두 해당 위치에서 취약점을 탐지하지 않았습니다."
            p["reason"] = "교차 검증 결과 취약점이 확인되지 않았습니다."
            p["action_text"] = "조치 불필요합니다."
            p["reassessed_severity"] = "LOW"
        result.append(p)
    return result
