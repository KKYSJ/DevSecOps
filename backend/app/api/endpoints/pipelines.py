"""
파이프라인 실행 이력 조회 엔드포인트
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()


@router.get("")
def list_pipelines(db: Session = Depends(get_db)):
    """파이프라인 실행 이력을 반환합니다."""
    from backend.app.models.pipeline_run import PipelineRun

    try:
        records = (
            db.query(PipelineRun)
            .order_by(PipelineRun.id.desc())
            .limit(50)
            .all()
        )
        pipelines = []
        for rec in records:
            data = rec.data or {}
            data["id"] = rec.id
            data["name"] = rec.name
            data["status"] = rec.status
            pipelines.append(data)
        return {"pipelines": pipelines, "total": len(pipelines), "source": "db"}
    except Exception:
        return {"pipelines": [], "total": 0, "source": "db"}


@router.get("/{pipeline_id}")
def get_pipeline(pipeline_id: int, db: Session = Depends(get_db)):
    """특정 파이프라인 실행 상세를 반환합니다."""
    from backend.app.models.pipeline_run import PipelineRun

    try:
        record = db.query(PipelineRun).filter(PipelineRun.id == pipeline_id).first()
        if record and record.data:
            data = dict(record.data)
            data["id"] = record.id
            data["name"] = record.name
            data["status"] = record.status
            return data
    except Exception:
        pass

    raise HTTPException(status_code=404, detail=f"파이프라인 ID {pipeline_id}를 찾을 수 없습니다.")
