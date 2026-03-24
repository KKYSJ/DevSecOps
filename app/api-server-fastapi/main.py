"""
이커머스 API 서버 (FastAPI 버전)
- AWS 교육용 프로젝트
- 로컬 모드 (Day 1-2): SQLite + 로컬 파일 + 인메모리 캐시
- AWS 모드 (Day 3-5): MySQL(RDS) + S3 + DynamoDB + Redis
"""

import os
import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.config.settings import settings
from app.config.database import init_database, close_database

# 라우터 임포트
from app.routes.auth import router as auth_router
from app.routes.products import router as products_router
from app.routes.reviews import router as reviews_router
from app.routes.cart import router as cart_router
from app.routes.orders import router as orders_router
from app.routes.upload import router as upload_router
from app.routes.health import router as health_router
from vulnerable_endpoints import router as vuln_demo_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 시작/종료 시 실행되는 라이프사이클 관리"""
    # 시작 시
    try:
        await init_database()
        print("========================================")
        print("  이커머스 API 서버 시작 (FastAPI)")
        print(f"  포트: {settings.PORT}")
        print(f"  DB: {settings.DB_TYPE}")
        print(f"  스토리지: {settings.STORAGE_TYPE}")
        print(f"  리뷰 저장소: {settings.REVIEW_STORE}")
        print(f"  캐시: {settings.CACHE_TYPE}")
        print(f"  큐: {settings.QUEUE_TYPE}")
        print("========================================")
    except Exception as e:
        print(f"[Server] 서버 시작 실패: {e}")
        raise

    yield

    # 종료 시
    await close_database()
    print("[Server] 서버 종료")


# ========================================
# FastAPI 앱 생성
# ========================================

app = FastAPI(
    title="이커머스 API",
    description="AWS 교육용 이커머스 API 서버 (FastAPI)",
    version="1.0.0",
    lifespan=lifespan,
)

# ========================================
# 미들웨어 설정
# ========================================

# CORS 설정 (모든 출처 허용 - 개발용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========================================
# 정적 파일 서빙 (업로드된 이미지)
# ========================================

# uploads 디렉토리 생성
settings.UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(settings.UPLOADS_DIR)), name="uploads")

# ========================================
# 라우트 설정
# ========================================

app.include_router(auth_router)
app.include_router(products_router)
app.include_router(reviews_router)
app.include_router(cart_router)
app.include_router(orders_router)
app.include_router(upload_router)
app.include_router(health_router)
app.include_router(vuln_demo_router)  # DAST 탐지용 의도적 취약 엔드포인트


# ========================================
# 에러 핸들링
# ========================================

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """404 처리"""
    return JSONResponse(
        status_code=404,
        content={"error": "요청한 리소스를 찾을 수 없습니다"},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """전역 에러 핸들러"""
    return JSONResponse(
        status_code=500,
        content={"error": "서버 내부 오류가 발생했습니다"},
    )


# ========================================
# HTTPException 핸들러 (detail -> error 변환)
# ========================================

from fastapi.exceptions import HTTPException as FastAPIHTTPException


@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(request: Request, exc: FastAPIHTTPException):
    """HTTPException의 detail을 error 키로 반환"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )


# ========================================
# 서버 실행
# ========================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",  # nosec B104 - container entrypoint must bind all interfaces
        port=settings.PORT,
        reload=True,
    )
