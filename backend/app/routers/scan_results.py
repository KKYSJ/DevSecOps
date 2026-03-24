from typing import Any, Callable, List, Optional, TypeVar, Union

import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.core.models import ScanResult
from backend.app.schemas.scan import (
    DASTScanResult,
    IaCScanResult,
    SCAScanResult,
    SASTScanResult,
)

router = APIRouter(prefix="/scan-results", tags=["scan-results"])

T = TypeVar("T")


def _parse_raw_data(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _ensure_list(data: Union[T, List[T]]) -> List[T]:
    # 단건/배열 입력을 모두 리스트로 통일
    return data if isinstance(data, list) else [data]


def _extract_location_summary(raw: dict) -> Optional[str]:
    """
    목록 조회용 location 요약
    - location이 dict면 path 또는 url 우선
    - 문자열이면 그대로 사용
    """
    if not isinstance(raw, dict):
        return None

    raw_location = raw.get("location")
    if isinstance(raw_location, dict):
        return raw_location.get("path") or raw_location.get("url")
    return raw_location


def _extract_taxonomy(raw: dict):
    """
    raw_data 안의 finding.taxonomy 추출
    """
    if not isinstance(raw, dict):
        return None

    finding = raw.get("finding", {})
    if isinstance(finding, dict):
        return finding.get("taxonomy")
    return None


def _base_scan_result_data(item: Any) -> dict:
    """
    모든 스키마에서 공통으로 들어가는 필드 추출
    """
    confidence = getattr(item.finding, "confidence", None)

    return {
        "schema_version": item.schema_version,
        "tool_name": item.tool.name,
        "tool_category": item.tool.category,
        "tool_version": item.tool.version,
        "project_name": item.pipeline.project_name,
        "repository": item.pipeline.repository,
        "branch": item.pipeline.branch,
        "commit_sha": item.pipeline.commit_sha,
        "workflow_run_id": item.pipeline.workflow_run_id,
        "scanned_at": item.pipeline.scanned_at,
        "finding_id": item.finding.id,
        "normalized_type": item.finding.normalized_type,
        "title": item.finding.title,
        "description": item.finding.description,
        "severity": item.finding.severity,
        "status": item.finding.status,
        "final_confidence_score": (
            confidence.final_confidence_score if confidence else None
        ),
    }


def _build_iac_result(item: IaCScanResult) -> ScanResult:
    """
    IaC 전용 DB 저장 객체 생성
    """
    data = _base_scan_result_data(item)
    location = getattr(item, "location", None)

    data.update(
        {
            "location_type": getattr(location, "type", None),
            "location_path": (
                getattr(location, "path", None) or getattr(location, "url", None)
            ),
            "resource_type": getattr(location, "resource_type", None),
            "resource_name": getattr(location, "resource_name", None),
            "raw_data": item.model_dump_json(),
        }
    )

    return ScanResult(**data)


def _build_sast_result(item: SASTScanResult) -> ScanResult:
    """
    SAST 전용 DB 저장 객체 생성
    """
    data = _base_scan_result_data(item)
    location = getattr(item, "location", None)

    data.update(
        {
            "location_type": getattr(location, "type", None),
            "location_path": (
                getattr(location, "path", None) or getattr(location, "url", None)
            ),
            "resource_type": getattr(location, "resource_type", None),
            "resource_name": getattr(location, "resource_name", None),
            "raw_data": item.model_dump_json(),
        }
    )

    return ScanResult(**data)


def _build_dast_result(item: DASTScanResult) -> ScanResult:
    """
    DAST 전용 DB 저장 객체 생성
    """
    data = _base_scan_result_data(item)
    location = getattr(item, "location", None)

    data.update(
        {
            "location_type": getattr(location, "type", None),
            "location_path": (
                getattr(location, "path", None) or getattr(location, "url", None)
            ),
            "resource_type": getattr(location, "resource_type", None),
            "resource_name": getattr(location, "resource_name", None),
            "raw_data": item.model_dump_json(),
        }
    )

    return ScanResult(**data)


def _build_sca_result(item: SCAScanResult) -> ScanResult:
    """
    SCA 전용 DB 저장 객체 생성
    현재 테이블 컬럼 기준으로는 SCA 상세 정보(package, version, cve 등)는 raw_data에 저장
    """
    data = _base_scan_result_data(item)

    data.update(
        {
            "location_type": None,
            "location_path": None,
            "resource_type": None,
            "resource_name": None,
            "raw_data": item.model_dump_json(),
        }
    )

    return ScanResult(**data)


def _save_scan_results(
    items: List[Any],
    db: Session,
    builder: Callable[[Any], ScanResult],
) -> dict:
    """
    공통 다건 저장 함수
    """
    db_results = [builder(item) for item in items]

    db.add_all(db_results)
    db.commit()

    for result in db_results:
        db.refresh(result)

    return {
        "status": "saved",
        "count": len(db_results),
        "ids": [result.id for result in db_results],
    }


@router.get("/")
def get_scan_results(db: Session = Depends(get_db)) -> List[dict]:
    """
    최신 스캔 결과를 우선 조회
    finding_id 기준으로 중복 제거
    """
    results = (
        db.query(ScanResult)
        .order_by(ScanResult.scanned_at.desc(), ScanResult.id.desc())
        .all()
    )

    seen = set()
    output: List[dict] = []

    for r in results:
        if not r.finding_id:
            continue

        # 같은 finding_id가 도구별로 겹칠 수 있으면 아래처럼 바꾸는 것도 가능:
        # dedupe_key = (r.tool_name, r.finding_id)
        dedupe_key = r.finding_id

        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        raw = _parse_raw_data(r.raw_data)

        output.append(
            {
                "id": r.id,
                "finding_id": r.finding_id,
                "title": r.title,
                "severity": r.severity,
                "tool_name": r.tool_name,
                "tool_category": r.tool_category,
                "project_name": r.project_name,
                "location": _extract_location_summary(raw),
                "confidence": r.final_confidence_score,
                "taxonomy": _extract_taxonomy(raw),
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
        "taxonomy": _extract_taxonomy(raw),
        "evidence": raw.get("evidence"),
        "remediation": raw.get("remediation"),
        "raw_data": raw,
    }


@router.post("/iac")
def receive_iac_scan_result(
    data: Union[IaCScanResult, List[IaCScanResult]],
    db: Session = Depends(get_db),
):
    items = _ensure_list(data)
    return _save_scan_results(items, db, _build_iac_result)


@router.post("/sca")
def receive_sca_scan_result(
    data: Union[SCAScanResult, List[SCAScanResult]],
    db: Session = Depends(get_db),
):
    items = _ensure_list(data)
    return _save_scan_results(items, db, _build_sca_result)


@router.post("/sast")
def receive_sast_scan_result(
    data: Union[SASTScanResult, List[SASTScanResult]],
    db: Session = Depends(get_db),
):
    items = _ensure_list(data)
    return _save_scan_results(items, db, _build_sast_result)


@router.post("/dast")
def receive_dast_scan_result(
    data: Union[DASTScanResult, List[DASTScanResult]],
    db: Session = Depends(get_db),
):
    items = _ensure_list(data)
    return _save_scan_results(items, db, _build_dast_result)
