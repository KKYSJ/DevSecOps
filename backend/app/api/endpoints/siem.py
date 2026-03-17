"""
SIEM 이벤트 요약 엔드포인트
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()

_EMPTY_SIEM = {
    "total_events": 0,
    "critical_events": 0,
    "high_events": 0,
    "medium_events": 0,
    "low_events": 0,
    "info_events": 0,
    "sources": [],
    "recent_critical_events": [],
    "event_trends": [],
    "top_event_types": [],
    "message": "SIEM 이벤트가 없습니다. AWS 연동 후 이벤트가 수집됩니다.",
}


@router.get("")
def get_siem_summary(db: Session = Depends(get_db)):
    """SIEM 이벤트 요약을 반환합니다."""
    from backend.app.models.siem_event import SiemEvent

    try:
        record = (
            db.query(SiemEvent)
            .filter(SiemEvent.name == "summary")
            .order_by(SiemEvent.id.desc())
            .first()
        )
        if record and record.data:
            return record.data
    except Exception:
        pass

    return _EMPTY_SIEM


@router.get("/events")
def list_siem_events(
    severity: str = None,
    source: str = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """SIEM 이벤트 목록을 반환합니다."""
    from backend.app.models.siem_event import SiemEvent

    try:
        records = (
            db.query(SiemEvent)
            .filter(SiemEvent.name != "summary")
            .order_by(SiemEvent.id.desc())
            .limit(limit)
            .all()
        )
        if records:
            events = [r.data for r in records if r.data]
            if severity:
                events = [e for e in events if e.get("severity", "").upper() == severity.upper()]
            if source:
                events = [e for e in events if source.lower() in e.get("source", "").lower()]
            return {"events": events[:limit], "total": len(events), "source": "db"}
    except Exception:
        pass

    return {"events": [], "total": 0, "source": "db"}
