"""
취약점 목록 조회 엔드포인트
"""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()


@router.get("")
def list_vulnerabilities(
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    category: Optional[str] = None,
    commit_hash: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """취약점 목록을 반환합니다. severity, tool, category 파라미터로 필터링 가능합니다."""
    from backend.app.models.scan import Scan
    from backend.app.models.vulnerability import Vulnerability

    try:
        query = db.query(Vulnerability)

        if severity:
            query = query.filter(Vulnerability.severity == severity.upper())
        if tool:
            query = query.filter(Vulnerability.tool == tool.lower())
        if category:
            query = query.filter(Vulnerability.category == category.upper())
        if commit_hash:
            query = query.join(Scan, Vulnerability.scan_id == Scan.id).filter(Scan.commit_hash == commit_hash)

        total = query.count()
        vulns = query.order_by(Vulnerability.id.desc()).offset(offset).limit(limit).all()

        return {
            "vulnerabilities": [
                {
                    "id": v.id,
                    "scan_id": v.scan_id,
                    "tool": v.tool,
                    "category": v.category,
                    "severity": v.severity,
                    "title": v.title,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "cwe_id": v.cwe_id,
                    "cve_id": v.cve_id,
                    "confidence": v.confidence,
                    "description": v.description,
                    "status": v.status,
                    "created_at": v.created_at.isoformat() if v.created_at else None,
                }
                for v in vulns
            ],
            "total": total,
            "offset": offset,
            "limit": limit,
        }

    except Exception:
        return {"vulnerabilities": [], "total": 0, "offset": offset, "limit": limit}
