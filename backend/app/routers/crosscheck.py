import json
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.models import CrosscheckReport, LLMCrosscheckResult
from backend.app.schemas.cross_validation import (
    CrosscheckReport as CrosscheckReportSchema,
)
from backend.app.schemas.crosscheck import (
    CrosscheckResultResponse,
    CrosscheckRunRequest,
    CrosscheckRunResponse,
)
from backend.app.services.crosscheck_service import run_crosscheck

router = APIRouter(prefix="/crosscheck", tags=["crosscheck"])


@router.get("/")
def get_crosscheck_reports(db: Session = Depends(get_db)) -> List[dict]:
    results = db.query(CrosscheckReport).all()
    return [
        {
            "id": row.id,
            "report_id": row.report_id,
            "generated_at": row.generated_at,
            "raw_data": row.raw_data,
        }
        for row in results
    ]


@router.post("/")
def receive_crosscheck_report(
    data: CrosscheckReportSchema,
    db: Session = Depends(get_db),
):
    db_result = CrosscheckReport(
        schema_version=data.schema_version,
        report_id=data.dashboard_report.report_id,
        generated_at=data.dashboard_report.generated_at,
        raw_data=data.model_dump_json(),
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return {"status": "saved", "id": db_result.id}


@router.post("/run", response_model=CrosscheckRunResponse)
def run_crosscheck_api(
    request: CrosscheckRunRequest,
    db: Session = Depends(get_db),
):
    try:
        saved = run_crosscheck(
            db=db,
            project_name=request.project_name,
            tool_category=request.tool_category,
            workflow_run_id=request.workflow_run_id,
        )
        return CrosscheckRunResponse(
            message="LLM crosscheck completed.",
            result_id=saved.id,
            project_name=saved.project_name,
            tool_category=saved.tool_category,
            workflow_run_id=saved.workflow_run_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail="The LLM response was not valid JSON.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Crosscheck failed: {str(exc)}",
        ) from exc


@router.get("/{result_id}", response_model=CrosscheckResultResponse)
def get_crosscheck_result(result_id: int, db: Session = Depends(get_db)):
    row = (
        db.query(LLMCrosscheckResult)
        .filter(LLMCrosscheckResult.id == result_id)
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="Crosscheck result not found.")

    return CrosscheckResultResponse(
        id=row.id,
        project_name=row.project_name,
        tool_category=row.tool_category,
        workflow_run_id=row.workflow_run_id,
        tool_a_name=row.tool_a_name,
        tool_b_name=row.tool_b_name,
        prompt_name=row.prompt_name,
        llm_model=row.llm_model,
        result_json=json.loads(row.result_json),
    )
