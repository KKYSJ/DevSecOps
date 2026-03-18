"""
LLM 교차 검증 프롬프트 생성 및 응답 파싱 모듈

- 업로드된 crosscheck_prompt.txt 규칙에 맞춰
  SAST / SCA / IaC / DAST 프롬프트를 생성한다.
- LLM 응답은 dashboard_report -> sections -> rows 구조의 JSON으로 기대한다.
- 파싱 실패 시 규칙 기반 fallback을 적용한다.
"""

from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# 카테고리별 메타 정보
_CATEGORY_META = {
    "SAST": {
        "tool_a_name": "SonarQube",
        "tool_b_name": "Semgrep",
        "section_id": "sast-sonarqube-semgrep",
        "title": "SAST 교차 검증: SonarQube vs Semgrep",
        "target_label_name": "코드 위치",
        "row_prefix": "sast",
        "single_tool": False,
        "summary_keys": ["critical_count", "high_count", "medium_count", "low_count"],
    },
    "SCA": {
        "tool_a_name": "Trivy",
        "tool_b_name": "Dependency-Check",
        "section_id": "sca-trivy-dependency-check",
        "title": "SCA 교차 검증: Trivy vs Dependency-Check",
        "target_label_name": "의존성 패키지",
        "row_prefix": "sca",
        "single_tool": False,
        "summary_keys": ["critical_count", "high_count", "medium_count", "low_count"],
    },
    "IaC": {
        "tool_a_name": "tfsec",
        "tool_b_name": "Checkov",
        "section_id": "iac-tfsec-checkov",
        "title": "IaC 교차 검증: tfsec vs Checkov",
        "target_label_name": "리소스",
        "row_prefix": "iac",
        "single_tool": False,
        "summary_keys": ["critical_count", "high_count", "medium_count", "low_count"],
    },
    "DAST": {
        "tool_a_name": "OWASP ZAP",
        "tool_b_name": None,
        "section_id": "dast-owasp-zap",
        "title": "DAST 분석 결과: OWASP ZAP",
        "target_label_name": "엔드포인트",
        "row_prefix": "dast",
        "single_tool": True,
        "summary_keys": ["high_count", "medium_count", "low_count"],
    },
}

_ALLOWED_JUDGEMENTS = {"TRUE_POSITIVE", "REVIEW_NEEDED", "FALSE_POSITIVE"}
_ALLOWED_CONFIDENCE = {"HIGH", "MED", "LOW"}
_ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_ALLOWED_TOOL_STATUS = {"detected", "not_detected"}


def build_cross_validation_prompt(category: str, matched_pairs: list[dict[str, Any]]) -> str:
    """
    LLM 교차 검증 프롬프트를 생성한다.

    Args:
        category: "SAST" | "SCA" | "IaC" | "DAST"
        matched_pairs: 엔진에서 매칭된 pair 목록

    Returns:
        LLM에 보낼 프롬프트 문자열
    """
    category = _normalize_category(category)
    meta = _get_meta(category)

    header = _build_header(category, meta)
    body = "\n\n".join(
        _format_pair_for_prompt(idx, pair, category, meta)
        for idx, pair in enumerate(matched_pairs)
    )

    output_schema = _build_output_schema_example(category, matched_pairs)
    footer = (
        "\n\n---\n\n"
        "위 데이터를 분석하여 아래 JSON 구조와 동일한 형태로만 응답하라.\n"
        "설명 문장, 코드블록 마크다운, 주석 없이 순수 JSON만 반환하라.\n"
        "reason과 action_text는 반드시 한국어로 작성하라.\n"
        "summary_cards는 rows의 최종 severity 기준으로 계산하라.\n\n"
        f"{json.dumps(output_schema, ensure_ascii=False, indent=2)}"
    )

    return header + "\n\n" + body + footer


def parse_llm_response(response_text: str, matched_pairs: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    """
    LLM 응답 JSON을 파싱하여 matched_pairs에 교차 검증 결과를 반영한다.

    기대 응답 구조:
    {
      "schema_version": "1.0.0",
      "dashboard_report": {
        "report_id": "crosscheck-001",
        "generated_at": "...",
        "summary_cards": {...},
        "sections": [
          {
            "category": "...",
            "rows": [...]
          }
        ]
      }
    }

    반환값은 원래 matched_pairs 순서를 유지한 list[dict].
    각 pair에 judgement_code, confidence_level, reason, action_text, ... 등을 추가한다.
    """
    category = _normalize_category(category)

    try:
        payload = _extract_json_object(response_text)
        rows = _extract_rows_from_response(payload)

        if not rows:
            logger.warning("LLM 응답에서 rows를 찾지 못했습니다. 규칙 기반 fallback을 사용합니다.")
            return _rule_based_fallback(matched_pairs, category)

        result_pairs = deepcopy(matched_pairs)

        for row in rows:
            idx = _resolve_pair_index(row)
            if idx is None or idx < 0 or idx >= len(result_pairs):
                continue

            pair = dict(result_pairs[idx])
            merged = _merge_row_into_pair(pair, row, category)
            result_pairs[idx] = merged

        # 혹시 일부 pair가 응답에 누락되었으면 fallback 기본값 채움
        for i, pair in enumerate(result_pairs):
            if not pair.get("judgement_code"):
                result_pairs[i] = _apply_single_fallback(pair, category)

        return result_pairs

    except Exception as e:
        logger.warning("LLM 응답 파싱 실패 (%s), 규칙 기반 fallback을 사용합니다.", e)
        return _rule_based_fallback(matched_pairs, category)


# =========================
# Prompt builder helpers
# =========================

def _build_header(category: str, meta: dict[str, Any]) -> str:
    tool_a = meta["tool_a_name"]
    tool_b = meta["tool_b_name"]
    target_label = meta["target_label_name"]

    if meta["single_tool"]:
        return f"""너는 보안 결과 정규화 및 분석을 수행하는 분석 엔진이다.

내가 제공하는 데이터는 {tool_a}가 탐지한 {category} 보안 취약점 목록이다.
단일 도구 분석이므로 교차 검증이 아니라 각 항목별 판정을 수행해야 한다.

반드시 다음 규칙을 따른다.
1. 출력은 설명 없이 JSON만 반환한다.
2. JSON 구조는 내가 제공한 예시 구조를 정확히 따른다.
3. 분석 대상은 활성 상태의 취약점만 기준으로 판단한다.
4. 각 row는 finding 1건 또는 엔진이 묶은 1개 pair를 기준으로 작성한다.
5. judgement_code는 TRUE_POSITIVE / REVIEW_NEEDED / FALSE_POSITIVE 중 하나만 사용한다.
6. confidence_level은 HIGH / MED / LOW 중 하나만 사용한다.
7. tool_a.status는 detected 또는 not_detected만 사용한다.
8. tool_b_name, tool_b.status, tool_b.display_result는 null로 둔다.
9. target_label_name은 "{target_label}"이다.
10. reason과 action_text는 반드시 한국어로 작성한다.
"""
    return f"""너는 보안 결과 정규화 및 교차검증을 수행하는 분석 엔진이다.

내가 제공하는 데이터는 {tool_a}와 {tool_b}가 탐지한 {category} 보안 취약점 pair 목록이다.
각 pair에 대해 같은 대상에서 같은 성격의 취약점인지 판단해야 한다.

반드시 다음 규칙을 따른다.
1. 출력은 설명 없이 JSON만 반환한다.
2. JSON 구조는 내가 제공한 예시 구조를 정확히 따른다.
3. 분석 대상은 활성 상태의 취약점만 기준으로 판단한다.
4. TRUE_POSITIVE는 두 도구가 동일한 {target_label}에서 같은 성격의 취약점을 탐지한 경우에 사용한다.
5. REVIEW_NEEDED는 한 도구만 탐지했거나 동일 취약점으로 단정하기 어려운 경우에 사용한다.
6. FALSE_POSITIVE는 명백한 오탐으로 판단되는 경우에만 사용한다.
7. judgement_code는 TRUE_POSITIVE / REVIEW_NEEDED / FALSE_POSITIVE 중 하나만 사용한다.
8. confidence_level은 HIGH / MED / LOW 중 하나만 사용한다.
9. tool_a.status / tool_b.status는 detected 또는 not_detected만 사용한다.
10. target_label_name은 "{target_label}"이다.
11. reason과 action_text는 반드시 한국어로 작성한다.
"""


def _format_pair_for_prompt(idx: int, pair: dict[str, Any], category: str, meta: dict[str, Any]) -> str:
    tool_a = meta["tool_a_name"]
    tool_b = meta["tool_b_name"]

    lines = [
        f"### pair_index: {idx}",
        f"- correlation_key: {pair.get('correlation_key', '')}",
        f"- category: {category}",
        f"- pair_severity: {pair.get('severity', 'UNKNOWN')}",
    ]

    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")

    lines.append(f"\n[{tool_a}]")
    lines.append(_format_finding(finding_a, category))

    if not meta["single_tool"]:
        lines.append(f"\n[{tool_b}]")
        lines.append(_format_finding(finding_b, category))

    return "\n".join(lines)


def _format_finding(finding: dict[str, Any] | None, category: str) -> str:
    if not finding:
        return "탐지 안 됨"

    parts: list[str] = []
    parts.append(f"- id: {finding.get('id') or finding.get('source_finding_id') or ''}")
    parts.append(f"- severity: {finding.get('severity', 'UNKNOWN')}")
    parts.append(f"- title: {finding.get('title') or ''}")
    parts.append(f"- rule_id: {finding.get('rule_id') or ''}")
    parts.append(f"- status: {finding.get('status', '')}")

    if category == "SAST":
        parts.append(f"- path: {finding.get('file_path') or finding.get('path') or ''}")
        parts.append(f"- line_start: {finding.get('line_number') or finding.get('line_start') or ''}")
        parts.append(f"- cwe_id: {finding.get('cwe_id') or ''}")
    elif category == "SCA":
        parts.append(f"- ecosystem: {finding.get('ecosystem') or ''}")
        parts.append(f"- package_name: {finding.get('package_name') or ''}")
        parts.append(f"- package_version: {finding.get('package_version') or ''}")
        parts.append(f"- purl: {finding.get('purl') or ''}")
        parts.append(f"- cve_id: {finding.get('cve_id') or ''}")
        parts.append(f"- ghsa_id: {finding.get('ghsa_id') or ''}")
        parts.append(f"- fixed_version: {finding.get('fixed_version') or finding.get('patched_versions') or ''}")
    elif category == "IaC":
        parts.append(f"- resource_address: {finding.get('resource_address') or ''}")
        parts.append(f"- resource: {finding.get('resource') or finding.get('_resource') or ''}")
        parts.append(f"- file_path: {finding.get('file_path') or finding.get('path') or ''}")
        parts.append(f"- line_number: {finding.get('line_number') or ''}")
    elif category == "DAST":
        parts.append(f"- url: {finding.get('url') or ''}")
        parts.append(f"- endpoint_group: {finding.get('endpoint_group') or ''}")
        parts.append(f"- method: {finding.get('http_method') or finding.get('method') or ''}")
        parts.append(f"- parameter: {finding.get('parameter') or ''}")
        parts.append(f"- normalized_type: {finding.get('normalized_type') or ''}")

    description = finding.get("description") or ""
    if description:
        if len(description) > 400:
            description = description[:400] + "..."
        parts.append(f"- description: {description}")

    return "\n".join(parts)


def _build_output_schema_example(category: str, matched_pairs: list[dict[str, Any]]) -> dict[str, Any]:
    meta = _get_meta(category)

    rows = []
    for idx, pair in enumerate(matched_pairs):
        row_id = f"{meta['row_prefix']}-{idx + 1:03d}"
        rows.append(_build_row_example(idx, row_id, pair, category, meta))

    summary_cards = _empty_summary_cards(category)

    return {
        "schema_version": "1.0.0",
        "dashboard_report": {
            "report_id": "crosscheck-001",
            "generated_at": _utc_now_iso(),
            "summary_cards": summary_cards,
            "sections": [
                {
                    "category": "IAC" if category == "IaC" else category,
                    "section_id": meta["section_id"],
                    "title": meta["title"],
                    "tool_a_name": meta["tool_a_name"],
                    "tool_b_name": meta["tool_b_name"],
                    "target_label_name": meta["target_label_name"],
                    "rows": rows,
                }
            ],
        },
    }


def _build_row_example(
    pair_index: int,
    row_id: str,
    pair: dict[str, Any],
    category: str,
    meta: dict[str, Any],
) -> dict[str, Any]:
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")

    severity = _normalize_severity(pair.get("severity"), category)
    title = _pick_title(finding_a, finding_b)
    target_label = _build_target_label_for_example(pair, category)

    row = {
        "row_id": row_id,
        "pair_index": pair_index,
        "correlation_key": pair.get("correlation_key", ""),
        "target_label": target_label,
        "severity": severity,
        "judgement_code": "TRUE_POSITIVE",
        "display_label": "취약",
        "confidence_level": "HIGH",
        "tool_a": {
            "tool_name": meta["tool_a_name"],
            "status": "detected",
            "display_result": f"{title}, {severity}" if finding_a else "탐지 안 됨",
            "finding_id": _finding_id(finding_a),
        },
        "tool_b": None if meta["single_tool"] else {
            "tool_name": meta["tool_b_name"],
            "status": "detected" if finding_b else "not_detected",
            "display_result": f"{title}, {severity}" if finding_b else "탐지 안 됨",
            "finding_id": _finding_id(finding_b),
        },
        "reason": "한국어로 판정 근거를 2~4문장으로 작성",
        "action_text": "한국어로 권장 조치 작성",
    }

    return row


# =========================
# Response parsing helpers
# =========================

def _extract_json_object(text: str) -> dict[str, Any]:
    """
    LLM 응답에서 JSON 객체를 최대한 안전하게 추출한다.
    """
    text = text.strip()

    # ```json ... ``` 우선 처리
    block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if block_match:
        candidate = block_match.group(1).strip()
        return json.loads(candidate)

    # 가장 바깥 JSON 객체 추출
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise json.JSONDecodeError("No JSON object found", text, 0)

    candidate = text[start:end + 1]
    return json.loads(candidate)


def _extract_rows_from_response(payload: dict[str, Any]) -> list[dict[str, Any]]:
    dashboard = payload.get("dashboard_report") or {}
    sections = dashboard.get("sections") or []
    if not sections:
        return []
    first_section = sections[0] or {}
    rows = first_section.get("rows") or []
    return rows if isinstance(rows, list) else []


def _resolve_pair_index(row: dict[str, Any]) -> int | None:
    """
    row에서 pair_index를 꺼낸다.
    없으면 row_id 끝 번호를 이용해 추정한다.
    """
    pair_index = row.get("pair_index")
    if isinstance(pair_index, int):
        return pair_index

    row_id = row.get("row_id")
    if isinstance(row_id, str):
        m = re.search(r"-(\d+)$", row_id)
        if m:
            return int(m.group(1)) - 1

    return None


def _merge_row_into_pair(pair: dict[str, Any], row: dict[str, Any], category: str) -> dict[str, Any]:
    judgement = row.get("judgement_code", "REVIEW_NEEDED")
    if judgement not in _ALLOWED_JUDGEMENTS:
        judgement = "REVIEW_NEEDED"

    confidence = row.get("confidence_level", "MED")
    if confidence not in _ALLOWED_CONFIDENCE:
        confidence = "MED"

    severity = _normalize_severity(row.get("severity") or pair.get("severity"), category)

    pair["row_id"] = row.get("row_id")
    pair["target_label"] = row.get("target_label", pair.get("correlation_key", ""))
    pair["severity"] = severity
    pair["judgement_code"] = judgement
    pair["display_label"] = row.get("display_label") or _display_label_for_judgement(judgement)
    pair["confidence_level"] = confidence
    pair["reason"] = row.get("reason", "")
    pair["action_text"] = row.get("action_text", "")
    pair["tool_a_result"] = _sanitize_tool_result(row.get("tool_a"), category, is_tool_b=False)
    pair["tool_b_result"] = _sanitize_tool_result(row.get("tool_b"), category, is_tool_b=True)
    return pair


def _sanitize_tool_result(tool_data: Any, category: str, is_tool_b: bool) -> dict[str, Any] | None:
    """
    LLM이 row.tool_a / row.tool_b를 어설프게 반환해도 최소한의 형식만 정리한다.
    """
    if tool_data is None:
        return None

    if not isinstance(tool_data, dict):
        return None

    status = tool_data.get("status")
    if is_tool_b and category == "DAST":
        return None

    if status not in _ALLOWED_TOOL_STATUS:
        status = "detected"

    return {
        "tool_name": tool_data.get("tool_name"),
        "status": status,
        "display_result": tool_data.get("display_result"),
        "finding_id": tool_data.get("finding_id"),
    }


# =========================
# Fallback helpers
# =========================

def _rule_based_fallback(matched_pairs: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    return [_apply_single_fallback(pair, category) for pair in deepcopy(matched_pairs)]


def _apply_single_fallback(pair: dict[str, Any], category: str) -> dict[str, Any]:
    meta = _get_meta(category)
    fa = pair.get("finding_a")
    fb = pair.get("finding_b")
    sev = _normalize_severity(pair.get("severity"), category)
    title = _pick_title(fa, fb)
    target_label = _build_target_label_from_pair(pair, category)

    row_id = pair.get("row_id")
    if not row_id:
        row_id = f"{meta['row_prefix']}-001"

    if category == "DAST":
        if fa:
            judgement = "REVIEW_NEEDED"
            confidence = "MED"
            reason = (
                f"{target_label}에서 {title} 성격의 취약점이 단일 DAST 도구로 탐지되었습니다. "
                "단일 도구 결과이므로 실제 악용 가능성과 영향 범위에 대한 추가 검토가 필요합니다."
            )
            action = "재현 테스트를 수행하고 요청/응답, 서버 설정, 관련 코드 경로를 함께 검토하세요."
        else:
            judgement = "FALSE_POSITIVE"
            confidence = "LOW"
            reason = "탐지 정보가 충분하지 않아 유효한 취약점으로 보기 어렵습니다."
            action = "원본 스캔 결과와 대상 엔드포인트를 다시 확인하세요."
    else:
        if fa and fb:
            judgement = "TRUE_POSITIVE"
            confidence = "HIGH"
            reason = (
                f"두 도구가 {target_label}에서 {title} 성격의 취약점을 함께 탐지했습니다. "
                "같은 대상과 같은 유형으로 교차 확인되어 실제 취약 가능성이 높습니다."
            )
            action = "관련 설정 또는 코드를 우선 수정하고 재스캔으로 개선 여부를 확인하세요."
        elif fa or fb:
            found_tool = meta["tool_a_name"] if fa else meta["tool_b_name"]
            judgement = "REVIEW_NEEDED"
            confidence = "MED"
            reason = (
                f"{found_tool}에서만 {target_label} 관련 {title} 취약점이 탐지되었습니다. "
                "동일 취약점으로 단정하기 어려우므로 원본 근거와 실제 영향 범위를 추가 검토해야 합니다."
            )
            action = "원본 근거, 대상 위치, 설정값 또는 버전 정보를 재검토하고 필요 시 수동 검증을 수행하세요."
        else:
            judgement = "FALSE_POSITIVE"
            confidence = "LOW"
            reason = "유효한 비교 대상이 없어 오탐 가능성이 높습니다."
            action = "매칭 로직과 원본 입력 데이터를 다시 확인하세요."

    pair["row_id"] = row_id
    pair["target_label"] = target_label
    pair["severity"] = sev
    pair["judgement_code"] = judgement
    pair["display_label"] = _display_label_for_judgement(judgement)
    pair["confidence_level"] = confidence
    pair["reason"] = reason
    pair["action_text"] = action
    pair["tool_a_result"] = {
        "tool_name": meta["tool_a_name"],
        "status": "detected" if fa else "not_detected",
        "display_result": f"{title}, {sev}" if fa else "탐지 안 됨",
        "finding_id": _finding_id(fa),
    }
    pair["tool_b_result"] = None if meta["single_tool"] else {
        "tool_name": meta["tool_b_name"],
        "status": "detected" if fb else "not_detected",
        "display_result": f"{title}, {sev}" if fb else "탐지 안 됨",
        "finding_id": _finding_id(fb),
    }
    return pair


# =========================
# Common utilities
# =========================

def _normalize_category(category: str) -> str:
    if category == "IAC":
        return "IaC"
    if category not in _CATEGORY_META and category.upper() in ("SAST", "SCA", "DAST"):
        return category.upper()
    return category


def _get_meta(category: str) -> dict[str, Any]:
    if category not in _CATEGORY_META:
        raise ValueError(f"지원하지 않는 category 입니다: {category}")
    return _CATEGORY_META[category]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _empty_summary_cards(category: str) -> dict[str, int]:
    meta = _get_meta(category)
    return {key: 0 for key in meta["summary_keys"]}


def _normalize_severity(value: Any, category: str) -> str:
    """
    프롬프트 규칙을 간단 반영한 severity 정규화.
    """
    if value is None:
        return "LOW" if category == "DAST" else "MEDIUM"

    sev = str(value).strip().upper()

    # 공통 정규화
    mapping = {
        "BLOCKER": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "HIGH": "HIGH",
        "MAJOR": "MEDIUM",
        "WARNING": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "MINOR": "LOW",
        "LOW": "LOW",
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "UNKNOWN": "LOW",
        "EXPERIMENT": "LOW",
        "INVENTORY": "LOW",
    }
    sev = mapping.get(sev, sev)

    if category == "DAST" and sev == "CRITICAL":
        # DAST 프롬프트는 HIGH/MEDIUM/LOW 집계를 사용
        return "HIGH"

    if sev not in _ALLOWED_SEVERITIES:
        return "LOW" if category == "DAST" else "MEDIUM"
    return sev


def _display_label_for_judgement(judgement: str) -> str:
    if judgement == "TRUE_POSITIVE":
        return "취약"
    if judgement == "REVIEW_NEEDED":
        return "확인 필요"
    return "오탐 가능"


def _finding_id(finding: dict[str, Any] | None) -> str | None:
    if not finding:
        return None
    return finding.get("id") or finding.get("source_finding_id")


def _pick_title(finding_a: dict[str, Any] | None, finding_b: dict[str, Any] | None) -> str:
    for finding in (finding_a, finding_b):
        if finding:
            title = finding.get("title")
            if title:
                return str(title)
            description = finding.get("description")
            if description:
                return str(description).split(".")[0][:80]
    return "보안 취약점"


def _build_target_label_for_example(pair: dict[str, Any], category: str) -> str:
    return _build_target_label_from_pair(pair, category)


def _build_target_label_from_pair(pair: dict[str, Any], category: str) -> str:
    fa = pair.get("finding_a") or {}
    fb = pair.get("finding_b") or {}
    finding = fa or fb

    if category == "SAST":
        path = finding.get("file_path") or finding.get("path") or ""
        line = finding.get("line_number") or finding.get("line_start")
        return f"{path}:{line}" if path and line else (path or pair.get("correlation_key", ""))
    if category == "SCA":
        eco = finding.get("ecosystem")
        pkg = finding.get("package_name")
        ver = finding.get("package_version")
        if eco and pkg and ver:
            return f"{eco}:{pkg}:{ver}"
        if eco and pkg:
            return f"{eco}:{pkg}"
        return pkg or pair.get("correlation_key", "")
    if category == "IaC":
        return (
            finding.get("resource_address")
            or finding.get("resource")
            or finding.get("_resource")
            or pair.get("correlation_key", "")
        )
    if category == "DAST":
        method = finding.get("http_method") or finding.get("method")
        endpoint = finding.get("endpoint_group") or _path_from_url(finding.get("url"))
        if method and endpoint:
            return f"{method} {endpoint}"
        return endpoint or finding.get("url") or pair.get("correlation_key", "")
    return pair.get("correlation_key", "")


def _path_from_url(url: str | None) -> str | None:
    if not url:
        return None
    m = re.match(r"^[a-zA-Z]+://[^/]+(/.*)$", url)
    if m:
        return m.group(1)
    return url