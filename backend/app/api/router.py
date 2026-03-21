from fastapi import APIRouter

from backend.app.api.endpoints import (
    cross_validation,
    isms,
    pipelines,
    reports,
    scans,
    siem,
    tools,
    vulnerabilities,
)
from backend.app.routers.crosscheck import router as crosscheck_router
from backend.app.routers.scan_results import router as scan_results_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(vulnerabilities.router, prefix="/vulns", tags=["vulnerabilities"])
api_router.include_router(cross_validation.router, prefix="/cross", tags=["cross-validation"])
api_router.include_router(tools.router, prefix="/tools", tags=["tools"])
api_router.include_router(isms.router, prefix="/isms", tags=["isms"])
api_router.include_router(siem.router, prefix="/siem", tags=["siem"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(pipelines.router, prefix="/pipelines", tags=["pipelines"])
api_router.include_router(scan_results_router)
api_router.include_router(crosscheck_router)
