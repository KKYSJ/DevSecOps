"""
DAST 취약점 탐지용 의도적 취약 엔드포인트
- Nuclei / ZAP 탐지 대상
- 보안 교육 및 데모 목적
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

router = APIRouter(tags=["vulnerable-demo"])


# 1. 환경변수 파일 노출 (CWE-200)
@router.get("/.env", response_class=PlainTextResponse)
async def exposed_env():
    return "DB_HOST=localhost\nDB_PASSWORD=admin123\nSECRET_KEY=super-secret-key-12345\n"


# 2. Git 설정 노출 (CWE-200)
@router.get("/.git/config", response_class=PlainTextResponse)
async def git_config():
    return "[core]\n    repositoryformatversion = 0\n[remote \"origin\"]\n    url = https://github.com/KKYSJ/DevSecOps.git\n"


# 3. 디버그 정보 노출 (CWE-215)
@router.get("/debug", response_class=JSONResponse)
async def debug_endpoint(request: Request):
    return {"debug": True, "env": "development", "database_url": "postgresql://admin:password@db:5432/app"}


# 4. 오픈 리다이렉트 (CWE-601)
@router.get("/redirect")
async def open_redirect(url: str = "https://example.com"):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=url)


# 5. 서버 정보 헤더 노출 (CWE-200)
@router.get("/api/status", response_class=JSONResponse)
async def server_status():
    response = JSONResponse(content={"status": "ok", "server": "FastAPI/0.104.1"})
    response.headers["X-Powered-By"] = "FastAPI/0.104.1"
    response.headers["Server"] = "uvicorn/0.24.0"
    response.headers["X-Debug-Mode"] = "true"
    return response
