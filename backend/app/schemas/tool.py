from pydantic import BaseModel

class ToolResponse(BaseModel):
    message: str = "not implemented"
