from pydantic import BaseModel

class SiemResponse(BaseModel):
    message: str = "not implemented"
