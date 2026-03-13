from fastapi import APIRouter
router = APIRouter()

@router.get("")
def get_siem():
    return {"message": "siem integrations ready"}
