import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from backend.app.core.config import GEMINI_MODEL, PROMPT_DIR
from backend.app.core.llm_client import generate_with_gemini
from backend.app.core.models import LLMCrosscheckResult, ScanResult


CATEGORY_CONFIG = {
    "IAC": {
        "tool_a_name": "tfsec",
        "tool_b_name": "checkov",
        "prompt_name": "iac_crosscheck_prompt.txt",
        "placeholder_a": "{{TFSEC_JSON}}",
        "placeholder_b": "{{CHECKOV_JSON}}",
    },
    "SAST": {
        "tool_a_name": "sonarqube",
        "tool_b_name": "semgrep",
        "prompt_name": "sast_crosscheck_prompt.txt",
        "placeholder_a": "{{SONARQUBE_JSON}}",
        "placeholder_b": "{{SEMGREP_JSON}}",
    },
    "SCA": {
        "tool_a_name": "trivy",
        "tool_b_name": "depcheck",
        "prompt_name": "sca_crosscheck_prompt.txt",
        "placeholder_a": "{{TRIVY_JSON}}",
        "placeholder_b": "{{DEPENDENCY_CHECK_JSON}}",
    },
    "DAST": {
        "tool_a_name": "zap",
        "tool_b_name": "nuclei",
        "prompt_name": "dast_crosscheck_prompt.txt",
        "placeholder_a": "{{ZAP_JSON}}",
        "placeholder_b": "{{NUCLEI_JSON}}",
    },
}


def parse_json_field(value: Any):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def load_prompt(prompt_name: str) -> str:
    prompt_path = Path(PROMPT_DIR) / prompt_name
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
    return prompt_path.read_text(encoding="utf-8")


def normalize_tool_name(tool_name: str) -> str:
    return (tool_name or "").strip().lower()


def get_rows_by_tool(
    db: Session,
    project_name: str,
    tool_category: str,
    tool_name: str,
    workflow_run_id: str | None = None,
):
    rows = (
        db.query(ScanResult)
        .filter(
            ScanResult.project_name == project_name,
            ScanResult.tool_category == tool_category,
        )
        .order_by(ScanResult.id.asc())
        .all()
    )

    filtered_rows = []
    for row in rows:
        row_tool_name = normalize_tool_name(getattr(row, "tool_name", ""))
        if row_tool_name != normalize_tool_name(tool_name):
            continue

        raw_data = parse_json_field(getattr(row, "raw_data", None)) or {}
        pipeline = raw_data.get("pipeline", {}) if isinstance(raw_data, dict) else {}

        if workflow_run_id and pipeline.get("workflow_run_id") != workflow_run_id:
            continue

        filtered_rows.append(row)

    return filtered_rows


def build_tool_bundle(rows: list, fallback_tool_name: str, fallback_category: str):
    if not rows:
        return {
            "schema_version": "1.0.0",
            "tool": {
                "name": fallback_tool_name,
                "category": fallback_category,
                "version": None,
            },
            "pipeline": {
                "project_name": None,
                "repository": None,
                "branch": None,
                "commit_sha": None,
                "workflow_run_id": None,
                "scanned_at": None,
            },
            "findings": [],
        }

    first_raw = parse_json_field(rows[0].raw_data) or {}
    first_tool = first_raw.get("tool", {}) if isinstance(first_raw, dict) else {}
    first_pipeline = first_raw.get("pipeline", {}) if isinstance(first_raw, dict) else {}

    findings = []
    for row in rows:
        raw = parse_json_field(row.raw_data) or {}
        finding_item = {
            "finding": raw.get("finding"),
            "location": raw.get("location"),
            "evidence": raw.get("evidence"),
            "remediation": raw.get("remediation"),
            "raw_detail": raw.get("raw_detail"),
        }
        findings.append(finding_item)

    return {
        "schema_version": first_raw.get("schema_version", "1.0.0"),
        "tool": {
            "name": first_tool.get("name", fallback_tool_name),
            "category": first_tool.get("category", fallback_category),
            "version": first_tool.get("version"),
        },
        "pipeline": {
            "project_name": first_pipeline.get("project_name"),
            "repository": first_pipeline.get("repository"),
            "branch": first_pipeline.get("branch"),
            "commit_sha": first_pipeline.get("commit_sha"),
            "workflow_run_id": first_pipeline.get("workflow_run_id"),
            "scanned_at": first_pipeline.get("scanned_at"),
        },
        "findings": findings,
    }


def build_crosscheck_prompt(
    prompt_template: str,
    tool_category: str,
    tool_a_json: dict,
    tool_b_json: dict | None = None,
) -> str:
    config = CATEGORY_CONFIG[tool_category]
    prompt = prompt_template

    prompt = prompt.replace(
        config["placeholder_a"],
        json.dumps(tool_a_json, ensure_ascii=False, indent=2),
    )

    if config["placeholder_b"]:
        prompt = prompt.replace(
            config["placeholder_b"],
            json.dumps(tool_b_json or {}, ensure_ascii=False, indent=2),
        )

    return prompt


def run_crosscheck(
    db: Session,
    project_name: str,
    tool_category: str,
    workflow_run_id: str | None = None,
):
    category = (tool_category or "").upper()

    if category not in CATEGORY_CONFIG:
        raise ValueError(f"Unsupported tool category: {tool_category}")

    config = CATEGORY_CONFIG[category]
    tool_a_name = config["tool_a_name"]
    tool_b_name = config["tool_b_name"]
    prompt_name = config["prompt_name"]

    tool_a_rows = get_rows_by_tool(
        db=db,
        project_name=project_name,
        tool_category=category,
        tool_name=tool_a_name,
        workflow_run_id=workflow_run_id,
    )
    tool_b_rows = get_rows_by_tool(
        db=db,
        project_name=project_name,
        tool_category=category,
        tool_name=tool_b_name,
        workflow_run_id=workflow_run_id,
    )

    if not tool_a_rows and not tool_b_rows:
        raise ValueError("No scan results found for crosscheck.")

    tool_a_json = build_tool_bundle(tool_a_rows, tool_a_name, category)
    tool_b_json = build_tool_bundle(tool_b_rows, tool_b_name, category)

    prompt_template = load_prompt(prompt_name)
    final_prompt = build_crosscheck_prompt(
        prompt_template=prompt_template,
        tool_category=category,
        tool_a_json=tool_a_json,
        tool_b_json=tool_b_json,
    )

    llm_response_text = generate_with_gemini(final_prompt)
    parsed_result = json.loads(llm_response_text)
    pipeline = tool_a_json.get("pipeline") or tool_b_json.get("pipeline") or {}

    row = LLMCrosscheckResult(
        project_name=project_name,
        tool_category=category,
        workflow_run_id=pipeline.get("workflow_run_id"),
        tool_a_name=tool_a_name,
        tool_b_name=tool_b_name,
        prompt_name=prompt_name,
        llm_model=GEMINI_MODEL,
        tool_a_input_json=json.dumps(tool_a_json, ensure_ascii=False),
        tool_b_input_json=json.dumps(tool_b_json, ensure_ascii=False),
        result_json=json.dumps(parsed_result, ensure_ascii=False),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return row
