"""
SecureFlow 리포트 생성 서비스
"""

import uuid
from datetime import datetime, timezone
from typing import Any


def generate_dashboard_report(scored_pairs: list[dict], pipeline_info: dict) -> dict:
    """
    스코어링된 쌍 목록과 파이프라인 정보로 대시보드 리포트 JSON 생성.

    Args:
        scored_pairs: scan_service.score_findings() 결과
        pipeline_info: 파이프라인 메타데이터 (commit_hash, project_name 등)

    Returns:
        대시보드 리포트 딕셔너리
    """
    from backend.app.services.scan_service import get_gate_decision

    gate_decision = get_gate_decision(scored_pairs)
    total_score = round(sum(p.get("row_score", 0.0) for p in scored_pairs), 2)

    # 카테고리별 섹션 구성
    sections: dict[str, list] = {"SAST": [], "SCA": [], "IaC": [], "DAST": []}
    for pair in scored_pairs:
        cat = pair.get("category", "SAST")
        sections.setdefault(cat, []).append({
            "correlation_key": pair.get("correlation_key", ""),
            "tool_a": pair.get("tool_a"),
            "tool_b": pair.get("tool_b"),
            "confidence": pair.get("confidence", "LOW"),
            "severity": pair.get("severity", "INFO"),
            "judgement_code": pair.get("judgement_code", "REVIEW_NEEDED"),
            "row_score": pair.get("row_score", 0.0),
            "reason": pair.get("reason", ""),
            "action_text": pair.get("action_text", ""),
            "finding_a": pair.get("finding_a"),
            "finding_b": pair.get("finding_b"),
        })

    # 심각도별 집계
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for pair in scored_pairs:
        sev = pair.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # 판정별 집계
    judgement_counts = {"TRUE_POSITIVE": 0, "REVIEW_NEEDED": 0, "FALSE_POSITIVE": 0}
    for pair in scored_pairs:
        jc = pair.get("judgement_code", "REVIEW_NEEDED")
        if jc in judgement_counts:
            judgement_counts[jc] += 1

    report_id = str(uuid.uuid4())

    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_name": pipeline_info.get("project_name", "secureflow"),
        "commit_hash": pipeline_info.get("commit_hash"),
        "gate_decision": gate_decision,
        "total_score": total_score,
        "summary": {
            "total_pairs": len(scored_pairs),
            "severity_counts": severity_counts,
            "judgement_counts": judgement_counts,
        },
        "sections": sections,
        "pipeline_info": pipeline_info,
    }


def list_reports(db: Any) -> list:
    """
    DB에서 저장된 리포트 목록 조회.
    실제 리포트는 ToolResult 테이블의 name='report' 레코드에 저장됨.

    Args:
        db: SQLAlchemy 세션

    Returns:
        리포트 메타데이터 리스트
    """
    from backend.app.models.tool_result import ToolResult

    try:
        records = (
            db.query(ToolResult)
            .filter(ToolResult.name == "report")
            .order_by(ToolResult.id.desc())
            .limit(50)
            .all()
        )
        reports = []
        for rec in records:
            data = rec.data or {}
            reports.append({
                "id": str(rec.id),
                "report_id": data.get("report_id", str(rec.id)),
                "generated_at": data.get("generated_at", ""),
                "project_name": data.get("project_name", "secureflow"),
                "commit_hash": data.get("commit_hash"),
                "gate_decision": data.get("gate_decision", "ALLOW"),
                "total_score": data.get("total_score", 0.0),
            })
        return reports
    except Exception:
        return []
