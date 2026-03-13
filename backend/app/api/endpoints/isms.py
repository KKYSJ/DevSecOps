from fastapi import APIRouter
router = APIRouter()

@router.get("")
def get_isms():
    return {"message": "isms checker ready"}
