from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()

_STAGES = {"sast", "sca", "iac", "dast"}


class GateSubmitRequest(BaseModel):
    stage: Literal["sast", "sca", "iac", "dast"]
    raw_result: Any
    commit_hash: str
    project_name: str = "secureflow"
    branch: str = "main"
    workflow_run_id: str | None = None
    source: str = "github_actions"


def _tool_result_name(stage: str) -> str:
    return f"llm_gate_{stage}"


def _build_gate_payload(body: GateSubmitRequest) -> dict[str, Any]:
    raw = body.raw_result if isinstance(body.raw_result, dict) else {"data": body.raw_result}
    llm_analysis = raw.get("llm_analysis") if isinstance(raw.get("llm_analysis"), dict) else {}
    matching = raw.get("matching") if isinstance(raw.get("matching"), dict) else {}

    return {
        "kind": "llm_gate",
        "source": body.source,
        "stage": body.stage,
        "project_name": body.project_name,
        "branch": body.branch,
        "commit_hash": body.commit_hash,
        "workflow_run_id": body.workflow_run_id,
        "decision": raw.get("decision"),
        "provider": llm_analysis.get("provider"),
        "model": llm_analysis.get("model"),
        "confidence": llm_analysis.get("confidence"),
        "matched_count": matching.get("matched_count"),
        "mismatch_count": matching.get("mismatch_count"),
        "divergence_ratio": raw.get("divergence_ratio"),
        "raw_result": raw,
    }


@router.post("")
def submit_gate(body: GateSubmitRequest, db: Session = Depends(get_db)):
    from backend.app.models.tool_result import ToolResult

    stage = body.stage.lower().strip()
    if stage not in _STAGES:
        raise HTTPException(status_code=400, detail=f"Unsupported gate stage: {body.stage}")

    record = ToolResult(
        name=_tool_result_name(stage),
        status="ok",
        data=_build_gate_payload(body),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "gate_id": record.id,
        "stage": stage,
        "commit_hash": body.commit_hash,
        "message": "CI LLM gate result saved.",
    }


@router.get("")
def list_gates(
    stage: str | None = None,
    commit_hash: str | None = None,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    from backend.app.models.tool_result import ToolResult

    query = db.query(ToolResult).filter(ToolResult.name.like("llm_gate_%"))
    if stage:
        normalized_stage = stage.lower().strip()
        if normalized_stage not in _STAGES:
            raise HTTPException(status_code=400, detail=f"Unsupported gate stage: {stage}")
        query = query.filter(ToolResult.name == _tool_result_name(normalized_stage))

    records = query.order_by(ToolResult.id.desc()).limit(limit).all()
    items: list[dict[str, Any]] = []
    for record in records:
        data = record.data or {}
        if commit_hash and data.get("commit_hash") != commit_hash:
            continue
        items.append(
            {
                "id": record.id,
                "stage": data.get("stage"),
                "project_name": data.get("project_name"),
                "branch": data.get("branch"),
                "commit_hash": data.get("commit_hash"),
                "workflow_run_id": data.get("workflow_run_id"),
                "decision": data.get("decision"),
                "provider": data.get("provider"),
                "model": data.get("model"),
                "confidence": data.get("confidence"),
                "matched_count": data.get("matched_count"),
                "mismatch_count": data.get("mismatch_count"),
                "divergence_ratio": data.get("divergence_ratio"),
            }
        )

    return {"gates": items, "total": len(items)}


@router.get("/{gate_id}")
def get_gate(gate_id: int, db: Session = Depends(get_db)):
    from backend.app.models.tool_result import ToolResult

    record = (
        db.query(ToolResult)
        .filter(
            ToolResult.id == gate_id,
            ToolResult.name.like("llm_gate_%"),
        )
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail=f"Gate result {gate_id} not found.")

    return {
        "id": record.id,
        "name": record.name,
        "status": record.status,
        "data": record.data or {},
    }
