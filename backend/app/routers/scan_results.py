from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.models import ScanResult
from app.schemas.scan import IaCScanResult, SCAScanResult, SASTScanResult, DASTScanResult
from typing import List, Optional
import json

router = APIRouter(prefix="/scan-results", tags=["scan-results"])


def _parse_raw_data(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


@router.get("/")
def get_scan_results(db: Session = Depends(get_db)) -> List[dict]:
    # 최신 스캔 결과를 우선으로 추출 (중복 finding_id 제거)
    results = (
        db.query(ScanResult)
        .order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc())
        .all()
    )

    seen: set = set()
    output: List[dict] = []

    for r in results:
        if not r.finding_id:
            continue
        if r.finding_id in seen:
            continue
        seen.add(r.finding_id)

        raw = _parse_raw_data(r.raw_data)
        finding = raw.get("finding", {}) if isinstance(raw, dict) else {}
        taxonomy = finding.get("taxonomy") if isinstance(finding, dict) else None
        raw_location = raw.get("location") if isinstance(raw, dict) else None

        # Normalize location: keep string locations as-is, otherwise attempt to read from a dict
        if isinstance(raw_location, dict):
            location = raw_location.get("path") or raw_location.get("url")
        else:
            location = raw_location

        output.append(
            {
                "id": r.id,
                "finding_id": r.finding_id,
                "title": r.title,
                "severity": r.severity,
                "tool_name": r.tool_name,
                "tool_category": r.tool_category,
                "project_name": r.project_name,
                "location": location,
                "confidence": r.final_confidence_score,
                "taxonomy": taxonomy,
            }
        )

    return output


@router.get("/{scan_id}")
def get_scan_result_detail(scan_id: int, db: Session = Depends(get_db)) -> dict:
    r = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Scan result not found")

    raw = _parse_raw_data(r.raw_data)

    return {
        "id": r.id,
        "finding_id": r.finding_id,
        "title": r.title,
        "description": r.description,
        "severity": r.severity,
        "tool_name": r.tool_name,
        "tool_category": r.tool_category,
        "project_name": r.project_name,
        "location": raw.get("location"),
        "confidence": r.final_confidence_score,
        "taxonomy": raw.get("finding", {}).get("taxonomy") if isinstance(raw.get("finding"), dict) else None,
        "evidence": raw.get("evidence"),
        "remediation": raw.get("remediation"),
        "raw_data": raw,
    }

@router.post("/iac")
def receive_iac_scan_result(data: IaCScanResult, db: Session = Depends(get_db)):
    # DB에 저장
    db_result = ScanResult(
        schema_version=data.schema_version,
        tool_name=data.tool.name,
        tool_category=data.tool.category,
        tool_version=data.tool.version,
        project_name=data.pipeline.project_name,
        repository=data.pipeline.repository,
        branch=data.pipeline.branch,
        commit_sha=data.pipeline.commit_sha,
        workflow_run_id=data.pipeline.workflow_run_id,
        scanned_at=data.pipeline.scanned_at,
        finding_id=data.finding.id,
        normalized_type=data.finding.normalized_type,
        title=data.finding.title,
        description=data.finding.description,
        severity=data.finding.severity,
        status=data.finding.status,
        final_confidence_score=data.finding.confidence.get("final_confidence_score") if data.finding.confidence else None,
        location_type=data.location.type,
        location_path=data.location.path or data.location.url,
        resource_type=data.location.resource_type,
        resource_name=data.location.resource_name,
        raw_data=data.model_dump_json()
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return {"status": "saved", "id": db_result.id}

@router.post("/sca")
def receive_sca_scan_result(data: SCAScanResult, db: Session = Depends(get_db)):
    # 비슷하게
    db_result = ScanResult(
        schema_version=data.schema_version,
        tool_name=data.tool.name,
        tool_category=data.tool.category,
        tool_version=data.tool.version,
        project_name=data.pipeline.project_name,
        repository=data.pipeline.repository,
        branch=data.pipeline.branch,
        commit_sha=data.pipeline.commit_sha,
        workflow_run_id=data.pipeline.workflow_run_id,
        scanned_at=data.pipeline.scanned_at,
        finding_id=data.finding.id,
        normalized_type=data.finding.normalized_type,
        title=data.finding.title,
        description=data.finding.description,
        severity=data.finding.severity,
        status=data.finding.status,
        final_confidence_score=data.finding.confidence.get("final_confidence_score") if data.finding.confidence else None,
        location_type=None,  # SCA has no location
        location_path=None,
        resource_type=None,
        resource_name=None,
        raw_data=data.model_dump_json()
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return {"status": "saved", "id": db_result.id}

@router.post("/sast")
def receive_sast_scan_result(data: SASTScanResult, db: Session = Depends(get_db)):
    # 비슷하게
    db_result = ScanResult(
        schema_version=data.schema_version,
        tool_name=data.tool.name,
        tool_category=data.tool.category,
        tool_version=data.tool.version,
        project_name=data.pipeline.project_name,
        repository=data.pipeline.repository,
        branch=data.pipeline.branch,
        commit_sha=data.pipeline.commit_sha,
        workflow_run_id=data.pipeline.workflow_run_id,
        scanned_at=data.pipeline.scanned_at,
        finding_id=data.finding.id,
        normalized_type=data.finding.normalized_type,
        title=data.finding.title,
        description=data.finding.description,
        severity=data.finding.severity,
        status=data.finding.status,
        final_confidence_score=data.finding.confidence.get("final_confidence_score") if data.finding.confidence else None,
        location_type=data.location.type,
        location_path=data.location.path or data.location.url,
        resource_type=data.location.resource_type,
        resource_name=data.location.resource_name,
        raw_data=data.model_dump_json()
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return {"status": "saved", "id": db_result.id}

@router.post("/dast")
def receive_dast_scan_result(data: DASTScanResult, db: Session = Depends(get_db)):
    # 비슷하게
    db_result = ScanResult(
        schema_version=data.schema_version,
        tool_name=data.tool.name,
        tool_category=data.tool.category,
        tool_version=data.tool.version,
        project_name=data.pipeline.project_name,
        repository=data.pipeline.repository,
        branch=data.pipeline.branch,
        commit_sha=data.pipeline.commit_sha,
        workflow_run_id=data.pipeline.workflow_run_id,
        scanned_at=data.pipeline.scanned_at,
        finding_id=data.finding.id,
        normalized_type=data.finding.normalized_type,
        title=data.finding.title,
        description=data.finding.description,
        severity=data.finding.severity,
        status=data.finding.status,
        final_confidence_score=data.finding.confidence.get("final_confidence_score") if data.finding.confidence else None,
        location_type=data.location.type,
        location_path=data.location.path or data.location.url,
        resource_type=data.location.resource_type,
        resource_name=data.location.resource_name,
        raw_data=data.model_dump_json()
    )
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return {"status": "saved", "id": db_result.id}