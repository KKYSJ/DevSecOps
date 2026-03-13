from fastapi import APIRouter
from backend.app.services.vuln_service import list_vulnerabilities
router = APIRouter()

@router.get("")
def get_vulnerabilities():
    return list_vulnerabilities()
