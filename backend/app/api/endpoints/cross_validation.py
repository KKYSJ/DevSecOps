"""
Cross-validation dashboard endpoints.
"""

from typing import Optional

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
    "message": "No cross-validation report is available yet.",
}


def _extract_commit_hash(payload: dict | None) -> str | None:
    if not isinstance(payload, dict):
        return None

    direct = payload.get("commit_hash")
    if direct:
        return direct

    gate_result = payload.get("gate_result")
    if isinstance(gate_result, dict):
        nested = gate_result.get("commit_hash")
        if nested:
            return nested

    return None


@router.get("")
def get_cross_validation(db: Session = Depends(get_db)):
    """Return the latest dashboard report with findings, if available."""
    from backend.app.models.tool_result import ToolResult

    try:
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

        if records and records[0] and records[0].data:
            return records[0].data
    except Exception:
        pass

    return _EMPTY_REPORT


@router.get("/history")
def get_cross_validation_history(db: Session = Depends(get_db)):
    """Return recent dashboard report history."""
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
            history.append(
                {
                    "id": str(rec.id),
                    "report_id": data.get("report_id", str(rec.id)),
                    "generated_at": data.get("generated_at", ""),
                    "project_name": data.get("project_name", "secureflow"),
                    "commit_hash": data.get("commit_hash"),
                    "gate_decision": data.get("gate_decision", "ALLOW"),
                    "total_score": data.get("total_score", 0.0),
                }
            )
        return {"history": history, "total": len(history)}
    except Exception:
        return {"history": [], "total": 0}


@router.get("/gates")
def get_llm_gates(commit_hash: Optional[str] = None, db: Session = Depends(get_db)):
    """Return LLM gate outputs for a single commit."""
    from backend.app.models.tool_result import ToolResult

    try:
        records = (
            db.query(ToolResult)
            .filter(ToolResult.name.like("llm-gate-%"))
            .filter(ToolResult.name != "llm-gate-judgments")
            .order_by(ToolResult.id.desc())
            .limit(30)
            .all()
        )

        resolved_commit = commit_hash
        if not resolved_commit:
            for rec in records:
                resolved_commit = _extract_commit_hash(rec.data or {})
                if resolved_commit:
                    break

        gates: dict[str, dict] = {}
        for rec in records:
            data = rec.data or {}
            record_commit = _extract_commit_hash(data)
            if resolved_commit and record_commit != resolved_commit:
                continue

            stage = data.get("stage", "unknown")
            if stage not in gates:
                gates[stage] = data

        judgments: dict[str, list] = {}
        summaries: dict[str, dict] = {}
        j_records = (
            db.query(ToolResult)
            .filter(ToolResult.name == "llm-gate-judgments")
            .order_by(ToolResult.id.desc())
            .limit(10)
            .all()
        )
        for j_rec in reversed(j_records):
            j_data = j_rec.data or {}
            record_commit = _extract_commit_hash(j_data)
            if resolved_commit and record_commit != resolved_commit:
                continue

            j_inner = j_data.get("judgments", {})
            if isinstance(j_inner, dict):
                for stage_key, items in j_inner.items():
                    if isinstance(items, list) and items:
                        judgments[stage_key] = items

            s_inner = j_data.get("summaries", {})
            if isinstance(s_inner, dict):
                for stage_key, sdata in s_inner.items():
                    if isinstance(sdata, dict) and (sdata.get("summary") or sdata.get("verdict")):
                        summaries[stage_key] = sdata

        return {
            "commit_hash": resolved_commit,
            "gates": gates,
            "judgments": judgments,
            "summaries": summaries,
        }
    except Exception:
        return {"commit_hash": commit_hash, "gates": {}, "judgments": {}, "summaries": {}}
