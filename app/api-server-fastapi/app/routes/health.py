"""
헬스 체크 및 설정 확인 라우터
- GET /api/health  : 서버 상태 확인
- GET /api/config  : 현재 서비스 설정 확인
"""

from datetime import datetime

from fastapi import APIRouter

from app.config.settings import settings

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health_check():
    """
    GET /api/health - 서버 상태 확인
    """
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "dbType": settings.DB_TYPE,
            "storageType": settings.STORAGE_TYPE,
            "reviewStore": settings.REVIEW_STORE,
            "cacheType": settings.CACHE_TYPE,
            "queueType": settings.QUEUE_TYPE,
        },
    }


@router.get("/api/config")
async def get_config():
    """
    GET /api/config - 현재 서비스 설정 확인
    """
    return {
        "storageType": settings.STORAGE_TYPE,
        "reviewStore": settings.REVIEW_STORE,
        "dbType": settings.DB_TYPE,
    }
