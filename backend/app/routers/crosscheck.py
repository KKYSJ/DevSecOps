from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.models import CrosscheckReport
from app.schemas.cross_validation import CrosscheckReport as CrosscheckReportSchema
from typing import List

router = APIRouter(prefix="/crosscheck", tags=["crosscheck"])

@router.get("/")
def get_crosscheck_reports(db: Session = Depends(get_db)) -> List[dict]:
    results = db.query(CrosscheckReport).all()
    return [{"id": r.id, "report_id": r.report_id, "generated_at": r.generated_at, "raw_data": r.raw_data} for r in results]

@router.post("/")
def receive_crosscheck_report(data: CrosscheckReportSchema, db: Session = Depends(get_db)):
    # DB에 저장
    db_result = CrosscheckReport(
        schema_version=data.schema_version,
        report_id=data.dashboard_report.report_id,
        generated_at=data.dashboard_report.generated_at,
        raw_data=data.model_dump_json()
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return {"status": "saved", "id": db_result.id}