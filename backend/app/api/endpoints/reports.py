from fastapi import APIRouter
router = APIRouter()

@router.get("")
def get_reports():
    return [{"name": "latest-report.json", "url": "/reports/latest"}]
