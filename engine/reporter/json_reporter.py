"""
scored matched_pair 목록에서 대시보드 리포트 JSON을 생성합니다.
"""

import logging
import uuid
from datetime import datetime, timezone

from engine.scorer.rules import compute_gate_decision

logger = logging.getLogger(__name__)

# 카테고리별 섹션 메타데이터
_SECTION_META = {
    "SAST": {
        "section_id": "sast-sonarqube-semgrep",
        "title": "SAST 교차 검증: SonarQube vs Semgrep",
        "tool_a_name": "SonarQube",
        "tool_b_name": "Semgrep",
        "target_label_name": "코드 위치",
    },
    "SCA": {
        "section_id": "sca-trivy-dependency-check",
        "title": "SCA 교차 검증: Trivy vs Dependency-Check",
        "tool_a_name": "Trivy",
        "tool_b_name": "Dependency-Check",
        "target_label_name": "의존성 패키지",
    },
    "IaC": {
        "section_id": "iac-tfsec-checkov",
        "title": "IaC 교차 검증: tfsec vs Checkov",
        "tool_a_name": "tfsec",
        "tool_b_name": "Checkov",
        "target_label_name": "리소스",
    },
    "DAST": {
        "section_id": "dast-owasp-zap",
        "title": "DAST 분석 결과: OWASP ZAP",
        "tool_a_name": "OWASP ZAP",
        "tool_b_name": None,
        "target_label_name": "엔드포인트",
    },
}

_ROW_ID_PREFIXES = {
    "SAST": "sast",
    "SCA": "sca",
    "IaC": "iac",
    "DAST": "dast",
}


def _build_target_label(pair: dict) -> str:
    """matched_pair에서 target_label을 생성합니다."""
    category = pair.get("category", "")
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")
    primary = finding_a or finding_b or {}

    if category == "SAST":
        file_path = primary.get("file_path") or ""
        line = primary.get("line_number")
        if file_path and line:
            return f"{file_path}:{line}"
        return file_path or "알 수 없음"

    elif category == "SCA":
        pkg_name = primary.get("package_name") or ""
        pkg_version = primary.get("package_version") or ""
        cve_id = primary.get("cve_id") or ""
        if pkg_name and pkg_version:
            label = f"{pkg_name}:{pkg_version}"
        elif pkg_name:
            label = pkg_name
        else:
            label = cve_id or "알 수 없음"
        if cve_id and cve_id not in label:
            label = f"{label} ({cve_id})"
        return label

    elif category == "IaC":
        resource = primary.get("_resource") or primary.get("resource") or ""
        if resource:
            # 속성 경로 포함된 경우 기본 리소스만 표시
            parts = resource.split(".")
            return ".".join(parts[:2]) if len(parts) >= 2 else resource
        file_path = primary.get("file_path") or ""
        line = primary.get("line_number")
        if file_path and line:
            return f"{file_path}:{line}"
        return file_path or "알 수 없음"

    elif category == "DAST":
        url = primary.get("url") or ""
        method = primary.get("http_method") or ""
        if method and url:
            # URL에서 path만 추출
            try:
                from urllib.parse import urlparse
                path = urlparse(url).path or url
            except Exception:
                path = url
            return f"{method} {path}"
        return url or "알 수 없음"

    return "알 수 없음"


def _build_tool_status(finding: dict | None, category: str) -> dict:
    """finding에서 tool status dict를 생성합니다."""
    if finding is None:
        return {
            "status": "not_detected",
            "display_result": "탐지 안 됨",
            "finding_id": None,
        }

    severity = finding.get("severity", "")
    title = finding.get("title") or finding.get("rule_id") or "알 수 없음"
    # 제목 축약
    if len(title) > 80:
        title = title[:80] + "..."

    display_result = f"{title}, {severity}" if severity else title

    return {
        "status": "detected",
        "display_result": display_result,
        "finding_id": finding.get("id"),
    }


def _build_row(pair: dict, row_id: str) -> dict:
    """matched_pair에서 리포트 row를 생성합니다."""
    category = pair.get("category", "")
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")

    target_label = _build_target_label(pair)
    tool_a_status = _build_tool_status(finding_a, category)
    tool_b_status = _build_tool_status(finding_b, category)

    # reason과 action_text 생성 (LLM에서 제공 안 된 경우 기본값)
    reason = pair.get("reason") or _default_reason(pair)
    action_text = pair.get("action_text") or _default_action_text(pair)

    return {
        "row_id": row_id,
        "target_label": target_label,
        "severity": pair.get("reassessed_severity", pair.get("severity", "MEDIUM")),
        "original_severity": pair.get("severity", "MEDIUM"),
        "judgement_code": pair.get("judgement_code", "REVIEW_NEEDED"),
        "display_label": pair.get("display_label", "확인 필요"),
        "confidence_level": pair.get("confidence_level", "MED"),
        "row_score": pair.get("row_score", 0.0),
        "tool_a": tool_a_status,
        "tool_b": tool_b_status,
        "title_ko": pair.get("title_ko", ""),
        "risk_summary": pair.get("risk_summary", ""),
        "reason": reason,
        "action_text": action_text,
    }


def _default_reason(pair: dict) -> str:
    """LLM 판정 없을 때 기본 reason을 생성합니다."""
    category = pair.get("category", "")
    judgement = pair.get("judgement_code", "REVIEW_NEEDED")
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")
    tool_a = pair.get("tool_a", "도구A")
    tool_b = pair.get("tool_b", "도구B")

    if judgement == "TRUE_POSITIVE":
        if category == "SAST":
            return (
                f"두 도구({tool_a}, {tool_b})가 동일한 코드 위치에서 같은 성격의 보안 취약점을 탐지했습니다. "
                "실제 취약 가능성이 높으므로 즉시 코드 검토 및 수정이 필요합니다."
            )
        elif category == "SCA":
            return (
                f"두 도구({tool_a}, {tool_b})가 동일한 의존성 패키지에서 같은 취약점을 탐지했습니다. "
                "실제 취약 가능성이 높으므로 즉시 패키지 업그레이드가 필요합니다."
            )
        elif category == "IaC":
            return (
                f"두 도구({tool_a}, {tool_b})가 동일한 IaC 리소스에서 같은 성격의 보안 설정 문제를 탐지했습니다. "
                "실제 취약 가능성이 높으므로 즉시 설정 수정이 필요합니다."
            )
        else:
            return "탐지된 취약점을 검토하고 필요한 조치를 취하세요."

    elif judgement == "REVIEW_NEEDED":
        detected_by = tool_a if finding_a else tool_b
        return (
            f"한 도구({detected_by})에서만 탐지되었거나 동일 취약점으로 단정하기 어려워 추가 검토가 필요합니다. "
            "수동으로 해당 결과를 검토하여 실제 취약 여부를 확인하세요."
        )

    return "해당 항목을 검토하세요."


def _default_action_text(pair: dict) -> str:
    """LLM 판정 없을 때 기본 action_text를 생성합니다."""
    category = pair.get("category", "")
    judgement = pair.get("judgement_code", "REVIEW_NEEDED")
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")
    primary = finding_a or finding_b or {}

    if judgement == "TRUE_POSITIVE":
        if category == "SAST":
            file_path = primary.get("file_path", "")
            line = primary.get("line_number", "")
            return f"{file_path}:{line} 코드를 즉시 수정하세요. 취약한 코드 패턴을 안전한 구현으로 교체하세요."
        elif category == "SCA":
            pkg = primary.get("package_name", "패키지")
            fixed = primary.get("fixed_version", "")
            if fixed:
                return f"{pkg}을(를) {fixed} 이상으로 즉시 업그레이드하세요."
            return f"{pkg}의 최신 보안 패치 버전으로 업그레이드하세요."
        elif category == "IaC":
            resource = primary.get("_resource") or primary.get("file_path", "해당 리소스")
            return f"{resource}의 보안 설정을 즉시 수정하세요."
        else:
            return "취약점을 즉시 수정하세요."
    else:
        if category == "SAST":
            return "코드를 재검토하고 실제 취약 여부를 확인하세요."
        elif category == "SCA":
            return "패키지 버전, 의존성 경로, 고정 가능 버전을 확인하고 실제 사용 여부를 검토하세요."
        elif category == "IaC":
            return "해당 리소스 설정을 재검토하고 보안 정책 준수 여부를 확인하세요."
        else:
            return "해당 항목을 재현 테스트하고 서버 설정 및 코드를 검토하세요."


def _build_section(category: str, pairs: list[dict]) -> dict:
    """카테고리의 모든 쌍에서 섹션을 생성합니다."""
    meta = _SECTION_META.get(category, {
        "section_id": f"{category.lower()}-unknown",
        "title": f"{category} 분석 결과",
        "tool_a_name": "도구A",
        "tool_b_name": "도구B",
        "target_label_name": "대상",
    })
    prefix = _ROW_ID_PREFIXES.get(category, category.lower())

    rows = []
    for idx, pair in enumerate(pairs):
        row_id = f"{prefix}-{idx + 1:03d}"
        try:
            row = _build_row(pair, row_id)
            rows.append(row)
        except Exception as e:
            logger.warning("row 생성 실패 (pair=%s): %s", pair.get("correlation_key"), e)
            continue

    return {
        "category": category,
        "section_id": meta["section_id"],
        "title": meta["title"],
        "tool_a_name": meta["tool_a_name"],
        "tool_b_name": meta["tool_b_name"],
        "target_label_name": meta["target_label_name"],
        "rows": rows,
    }


def generate(matched_pairs: list[dict], pipeline_info: dict = None) -> dict:
    """scored matched_pair 목록에서 dashboard_report JSON을 생성합니다.

    Args:
        matched_pairs: 점수가 계산된 matched_pair 목록
        pipeline_info: 파이프라인 정보 (report_id 등) - 옵션

    Returns:
        dashboard_report JSON dict
    """
    if pipeline_info is None:
        pipeline_info = {}

    generated_at = datetime.now(timezone.utc).isoformat()
    report_id = pipeline_info.get("report_id") or f"crosscheck-{uuid.uuid4().hex[:8]}"

    # 카테고리별로 그룹화
    pairs_by_category: dict[str, list[dict]] = {}
    for pair in matched_pairs:
        cat = pair.get("category", "UNKNOWN")
        pairs_by_category.setdefault(cat, []).append(pair)

    # 섹션 생성 (카테고리 순서 유지)
    category_order = ["SAST", "SCA", "IaC", "DAST"]
    sections = []
    for cat in category_order:
        if cat in pairs_by_category:
            section = _build_section(cat, pairs_by_category[cat])
            sections.append(section)

    # 알 수 없는 카테고리도 처리
    for cat, pairs in pairs_by_category.items():
        if cat not in category_order:
            section = _build_section(cat, pairs)
            sections.append(section)

    # summary_cards 집계
    all_rows = [row for section in sections for row in section.get("rows", [])]
    total_score = sum(row.get("row_score", 0) for row in all_rows)

    summary_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in all_rows:
        sev = row.get("severity", "INFO")
        summary_counts[sev] = summary_counts.get(sev, 0) + 1

    # 게이트 결정
    gate_decision = compute_gate_decision(matched_pairs)

    return {
        "schema_version": "1.0.0",
        "dashboard_report": {
            "report_id": report_id,
            "generated_at": generated_at,
            "summary_cards": {
                "critical_count": summary_counts["CRITICAL"],
                "high_count": summary_counts["HIGH"],
                "medium_count": summary_counts["MEDIUM"],
                "low_count": summary_counts["LOW"],
                "total_score": round(total_score, 2),
                "gate_decision": gate_decision,
            },
            "sections": sections,
        },
    }
