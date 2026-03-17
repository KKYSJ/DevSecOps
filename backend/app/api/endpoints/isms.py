"""
ISMS-P 점검 결과 엔드포인트
"""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()

_EMPTY_ISMS = {
    "check_id": None,
    "overall": {"total": 0, "passed": 0, "failed": 0, "pass_rate": 0.0},
    "categories": [],
    "aws_checks": {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "services_checked": [],
        "critical_findings": [],
    },
    "message": "ISMS-P 점검 결과가 없습니다. AWS 자격증명 설정 후 /isms/run을 실행하세요.",
}


@router.get("")
def get_isms_result(db: Session = Depends(get_db)):
    """최신 ISMS-P 점검 결과를 반환합니다."""
    from backend.app.models.isms_check import IsmsCheck

    try:
        record = (
            db.query(IsmsCheck)
            .order_by(IsmsCheck.id.desc())
            .first()
        )
        if record and record.data:
            return record.data
    except Exception:
        pass

    return _EMPTY_ISMS


@router.post("/run")
def run_isms_check(
    region: Optional[str] = "ap-northeast-2",
    db: Session = Depends(get_db),
):
    """ISMS-P AWS 점검을 트리거합니다."""
    from backend.app.models.isms_check import IsmsCheck
    import os

    has_aws_creds = bool(
        os.environ.get("AWS_ACCESS_KEY_ID") or
        os.environ.get("AWS_PROFILE") or
        os.environ.get("AWS_ROLE_ARN")
    )

    if not has_aws_creds:
        return {
            "status": "skipped",
            "message": "AWS 자격증명이 없습니다. 배포 후 AWS 환경에서 실행하세요.",
        }

    try:
        from backend.app.services.ismsp.checker import run_isms_checks
        result = run_isms_checks(region=region)

        record = IsmsCheck(
            name=f"isms-check-{region}",
            status="completed",
            data=result,
        )
        db.add(record)
        db.commit()

        return {"status": "completed", "result": result}
    except ImportError:
        return {"status": "error", "message": "ISMS 점검 모듈이 설치되지 않았습니다."}
    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}
