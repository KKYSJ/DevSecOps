"""
교차 검증 대시보드 엔드포인트
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()

_EMPTY_REPORT = {
    "report_id": None,
    "gate_decision": "ALLOW",
    "total_score": 0.0,
    "summary": {
        "total_pairs": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "judgement_counts": {"TRUE_POSITIVE": 0, "REVIEW_NEEDED": 0, "FALSE_POSITIVE": 0},
    },
    "sections": {"SAST": [], "SCA": [], "IaC": [], "DAST": []},
    "message": "스캔 결과가 없습니다. CI 파이프라인을 실행하세요.",
}


@router.get("")
def get_cross_validation(db: Session = Depends(get_db)):
    """최신 교차 검증 대시보드 리포트를 반환합니다."""
    from backend.app.models.tool_result import ToolResult

    try:
        # findings가 있는 최신 report를 우선 반환
        from sqlalchemy import cast, Integer
        from sqlalchemy.dialects.postgresql import JSONB

        records = (
            db.query(ToolResult)
            .filter(ToolResult.name == "report")
            .order_by(ToolResult.id.desc())
            .limit(10)
            .all()
        )
        for record in records:
            if record and record.data:
                total = record.data.get("summary", {}).get("total_findings", 0)
                if total > 0:
                    return record.data

        # findings 있는 게 없으면 최신 반환
        if records and records[0] and records[0].data:
            return records[0].data
    except Exception:
        pass

    return _EMPTY_REPORT


@router.get("/history")
def get_cross_validation_history(db: Session = Depends(get_db)):
    """교차 검증 리포트 이력을 반환합니다."""
    from backend.app.models.tool_result import ToolResult

    try:
        records = (
            db.query(ToolResult)
            .filter(ToolResult.name == "report")
            .order_by(ToolResult.id.desc())
            .limit(20)
            .all()
        )
        history = []
        for rec in records:
            data = rec.data or {}
            history.append({
                "id": str(rec.id),
                "report_id": data.get("report_id", str(rec.id)),
                "generated_at": data.get("generated_at", ""),
                "project_name": data.get("project_name", "secureflow"),
                "commit_hash": data.get("commit_hash"),
                "gate_decision": data.get("gate_decision", "ALLOW"),
                "total_score": data.get("total_score", 0.0),
            })
        return {"history": history, "total": len(history)}
    except Exception:
        return {"history": [], "total": 0}


@router.get("/gates")
def get_llm_gates(db: Session = Depends(get_db)):
    """CI의 LLM gate 결과를 반환합니다."""
    from backend.app.models.tool_result import ToolResult

    try:
        records = (
            db.query(ToolResult)
            .filter(ToolResult.name.like("llm-gate-%"))
            .order_by(ToolResult.id.desc())
            .limit(10)
            .all()
        )
        gates = {}
        for rec in records:
            data = rec.data or {}
            stage = data.get("stage", "unknown")
            if stage not in gates:  # 카테고리별 최신 1건만
                gates[stage] = data

        # 개별 판정 결과 (judgments) — 여러 건 merge
        judgments: dict = {}
        j_records = (
            db.query(ToolResult)
            .filter(ToolResult.name == "llm-gate-judgments")
            .order_by(ToolResult.id.desc())
            .limit(5)
            .all()
        )
        for j_rec in reversed(j_records):  # 오래된 것부터 → 최신이 덮어씀
            j_data = j_rec.data or {}
            j_inner = j_data.get("judgments", {})
            if isinstance(j_inner, dict):
                for stage_key, items in j_inner.items():
                    if isinstance(items, list) and len(items) > 0:
                        judgments[stage_key] = items

        return {"gates": gates, "judgments": judgments}
    except Exception:
        return {"gates": {}, "judgments": {}}
