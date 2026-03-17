from fastapi import APIRouter
from app.api.endpoints import scans, vulnerabilities, cross_validation, tools, isms, siem, reports, pipelines, crosscheck, scan_results

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(vulnerabilities.router, prefix="/vulns", tags=["vulnerabilities"])
api_router.include_router(cross_validation.router, prefix="/cross", tags=["cross-validation"])
api_router.include_router(tools.router, prefix="/tools", tags=["tools"])
api_router.include_router(isms.router, prefix="/isms", tags=["isms"])
api_router.include_router(siem.router, prefix="/siem", tags=["siem"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(pipelines.router, prefix="/pipelines", tags=["pipelines"])
api_router.include_router(crosscheck.router, prefix="/crosscheck", tags=["crosscheck"])
api_router.include_router(scan_results.router, prefix="/scan-results", tags=["scan-results"])
