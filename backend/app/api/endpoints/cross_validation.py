from fastapi import APIRouter
router = APIRouter()

@router.get("")
def get_cross_validation():
    return {"message": "cross validation ready"}
