import json
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.models import CrosscheckReport, LLMCrosscheckResult
from app.services.crosscheck_service import run_crosscheck
from app.schemas.cross_validation import CrosscheckReport as CrosscheckReportSchema
from app.schemas.crosscheck import (
    CrosscheckRunRequest,
    CrosscheckRunResponse,
    CrosscheckResultResponse,
)

router = APIRouter(prefix="/crosscheck", tags=["crosscheck"])


@router.get("/")
def get_crosscheck_reports(db: Session = Depends(get_db)) -> List[dict]:
    results = db.query(CrosscheckReport).all()
    return [
        {
            "id": r.id,
            "report_id": r.report_id,
            "generated_at": r.generated_at,
            "raw_data": r.raw_data,
        }
        for r in results
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
            message="LLM 교차검증이 완료되었습니다.",
            result_id=saved.id,
            project_name=saved.project_name,
            tool_category=saved.tool_category,
            workflow_run_id=saved.workflow_run_id,
        )

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="LLM 응답이 올바른 JSON 형식이 아닙니다.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"교차검증 실행 중 오류가 발생했습니다: {str(e)}",
        )


@router.get("/{result_id}", response_model=CrosscheckResultResponse)
def get_crosscheck_result(result_id: int, db: Session = Depends(get_db)):
    row = (
        db.query(LLMCrosscheckResult)
        .filter(LLMCrosscheckResult.id == result_id)
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="결과를 찾을 수 없습니다.")

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