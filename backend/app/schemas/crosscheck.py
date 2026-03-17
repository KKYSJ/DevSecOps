from pydantic import BaseModel
from typing import Any, Optional


class CrosscheckRunRequest(BaseModel):
    project_name: str
    tool_category: str
    workflow_run_id: Optional[str] = None


class CrosscheckRunResponse(BaseModel):
    message: str
    result_id: int
    project_name: str
    tool_category: str
    workflow_run_id: Optional[str] = None


class CrosscheckResultResponse(BaseModel):
    id: int
    project_name: str
    tool_category: str
    workflow_run_id: Optional[str] = None
    tool_a_name: str
    tool_b_name: str
    prompt_name: str
    llm_model: str
    result_json: Any