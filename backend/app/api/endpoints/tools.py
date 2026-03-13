from fastapi import APIRouter
router = APIRouter()

@router.get("")
def get_tools():
    return [{"name": "semgrep", "status": "enabled"}]
