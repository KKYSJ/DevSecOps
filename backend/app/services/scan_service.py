from backend.app.schemas.scan import ScanCreate

def trigger_scan(payload: ScanCreate) -> dict:
    return {"id": 1, "status": "queued", "branch": payload.branch, "repository_url": payload.repository_url}
