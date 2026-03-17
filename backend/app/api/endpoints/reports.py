"""
리포트 목록 조회 및 다운로드 엔드포인트
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.services import report_service

router = APIRouter()


@router.get("")
def list_reports(db: Session = Depends(get_db)):
    """저장된 리포트 목록을 반환합니다."""
    try:
        reports = report_service.list_reports(db)
        return {"reports": reports or [], "total": len(reports or []), "source": "db"}
    except Exception:
        return {"reports": [], "total": 0, "source": "db"}


@router.get("/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db)):
    """특정 리포트를 반환합니다."""
    from backend.app.models.tool_result import ToolResult

    try:
        try:
            rec_id = int(report_id)
            record = db.query(ToolResult).filter(
                ToolResult.id == rec_id,
                ToolResult.name == "report",
            ).first()
        except ValueError:
            records = db.query(ToolResult).filter(ToolResult.name == "report").all()
            record = next(
                (r for r in records if isinstance(r.data, dict) and r.data.get("report_id") == report_id),
                None,
            )

        if record and record.data:
            return record.data

        raise HTTPException(status_code=404, detail=f"리포트 ID {report_id}를 찾을 수 없습니다.")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """리포트 JSON을 다운로드합니다."""
    return get_report(report_id, db)
