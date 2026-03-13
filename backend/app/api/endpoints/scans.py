from fastapi import APIRouter
from backend.app.schemas.scan import ScanCreate
from backend.app.services.scan_service import trigger_scan
router = APIRouter()

@router.post("")
def create_scan(payload: ScanCreate):
    return trigger_scan(payload)

@router.get("")
def list_scans():
    return [{"id": 1, "status": "completed"}]
