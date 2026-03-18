"""
취약점 서비스 - DB에서 취약점 목록 조회
"""

from typing import Optional


def list_vulnerabilities(
    db=None,
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """취약점 목록을 DB에서 반환합니다."""
    if db is not None:
        try:
            from backend.app.models.vulnerability import Vulnerability
            query = db.query(Vulnerability)
            if severity:
                query = query.filter(Vulnerability.severity == severity.upper())
            vulns = query.offset(offset).limit(limit).all()
            return [
                {
                    "id": str(v.id),
                    "title": v.title,
                    "severity": v.severity,
                    "file_path": v.file_path,
                    "cwe_id": v.cwe_id,
                    "confidence": v.confidence,
                    "description": v.description,
                }
                for v in vulns
            ]
        except Exception:
            pass

    return []
