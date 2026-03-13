from pydantic import BaseModel

class ScanCreate(BaseModel):
    repository_url: str | None = None
    branch: str = "main"

class ScanResponse(BaseModel):
    id: int
    status: str
