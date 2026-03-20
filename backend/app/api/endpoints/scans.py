"""
스캔 제출 및 조회 엔드포인트
"""

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.services import scan_service

router = APIRouter()

_TOOL_CATEGORY = {
    "sonarqube": "SAST", "semgrep": "SAST",
    "trivy": "SCA",      "depcheck": "SCA",
    "tfsec": "IaC",      "checkov": "IaC",
    "zap": "DAST",
}


class ScanSubmitRequest(BaseModel):
    tool: str           # sonarqube | semgrep | trivy | depcheck | tfsec | checkov | zap
    raw_result: Any
    commit_hash: str    # 필수 — 동일 커밋의 스캔들을 Pipeline으로 묶는 키
    project_name: Optional[str] = "secureflow"
    branch: Optional[str] = "main"


class AnalyzeRequest(BaseModel):
    commit_hash: Optional[str] = None  # 특정 커밋 기준으로 분석 (없으면 최신)
    phase: Optional[int] = 2           # 1 = Phase1(SAST/SCA/IaC), 2 = Phase2(+DAST, 최종)


def _upsert_pipeline(db: Session, scan_id: int, body: ScanSubmitRequest, category: str):
    """commit_hash 기준으로 Pipeline row를 생성하거나 scan_id를 추가합니다."""
    from backend.app.models.pipeline_run import PipelineRun

    pipeline = (
        db.query(PipelineRun)
        .filter(PipelineRun.commit_hash == body.commit_hash)
        .first()
    )

    if pipeline:
        # 기존 파이프라인에 scan_id 추가
        current_ids = list(pipeline.scan_ids or [])
        if scan_id not in current_ids:
            current_ids.append(scan_id)
        pipeline.scan_ids = current_ids

        # DAST 스캔이 들어오면 Phase 2로 전환
        if category == "DAST" and pipeline.status == "scanning_phase1":
            pipeline.status = "scanning_phase2"
    else:
        # 새 파이프라인 생성
        initial_status = "scanning_phase2" if category == "DAST" else "scanning_phase1"
        pipeline = PipelineRun(
            project_name=body.project_name or "secureflow",
            commit_hash=body.commit_hash,
            branch=body.branch or "main",
            status=initial_status,
            scan_ids=[scan_id],
        )
        db.add(pipeline)


@router.post("")
def submit_scan(body: ScanSubmitRequest, db: Session = Depends(get_db)):
    """
    원시 도구 스캔 결과를 제출합니다.
    - commit_hash 기준으로 Pipeline row 생성 또는 업데이트
    - status=received 로 저장 후 Celery 태스크 트리거, scan_id 즉시 반환
    """
    tool = body.tool.lower().strip()
    if tool not in scan_service.PARSERS:
        raise HTTPException(
            status_code=400,
            detail=f"지원하지 않는 도구: {tool}. 지원 목록: {list(scan_service.PARSERS.keys())}",
        )

    from backend.app.models.scan import Scan

    category = _TOOL_CATEGORY.get(tool)
    raw = body.raw_result if isinstance(body.raw_result, dict) else {"data": body.raw_result}

    scan = Scan(
        tool=tool,
        category=category,
        project_name=body.project_name or "secureflow",
        commit_hash=body.commit_hash,
        raw_result=raw,
        status="received",
    )
    db.add(scan)
    db.flush()  # scan.id 확보 (commit 전)

    # Pipeline upsert
    _upsert_pipeline(db, scan.id, body, category)
    db.commit()
    db.refresh(scan)

    # Celery 태스크 트리거 (Redis 없으면 동기 폴백)
    from backend.app.workers.scan_worker import process_scan, _process_scan_sync
    try:
        process_scan.delay(scan.id)
        async_mode = True
    except Exception:
        _process_scan_sync(scan.id)
        db.refresh(scan)
        async_mode = False

    return {
        "scan_id": scan.id,
        "tool": tool,
        "category": category,
        "project_name": scan.project_name,
        "commit_hash": scan.commit_hash,
        "status": scan.status,
        "async": async_mode,
        "message": "백그라운드 처리 중" if async_mode else "처리 완료",
    }


@router.get("")
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    """모든 스캔 제출 목록을 반환합니다."""
    from backend.app.models.scan import Scan
    from sqlalchemy import func as sqlfunc
    from backend.app.models.vulnerability import Vulnerability

    try:
        scans = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
        result = []
        for s in scans:
            findings_count = (
                db.query(sqlfunc.count(Vulnerability.id))
                .filter(Vulnerability.scan_id == s.id)
                .scalar() or 0
            )
            result.append({
                "id": s.id,
                "tool": s.tool,
                "category": s.category,
                "project_name": s.project_name,
                "branch": "main",
                "commit_hash": s.commit_hash,
                "findings": findings_count,
                "status": s.status,
                "time": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else None,
            })
        return {"scans": result, "total": len(result)}
    except Exception:
        return {"scans": [], "total": 0}


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """특정 스캔의 상세 정보와 발견 사항을 반환합니다."""
    from backend.app.models.scan import Scan
    from backend.app.models.vulnerability import Vulnerability

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"스캔 ID {scan_id}를 찾을 수 없습니다.")

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    findings = [
        {
            "id": v.id,
            "tool": v.tool,
            "category": v.category,
            "severity": v.severity,
            "title": v.title,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "cwe_id": v.cwe_id,
            "cve_id": v.cve_id,
            "description": v.description,
            "status": v.status,
        }
        for v in vulns
    ]

    return {
        "scan_id": scan.id,
        "tool": scan.tool,
        "category": scan.category,
        "project_name": scan.project_name,
        "commit_hash": scan.commit_hash,
        "status": scan.status,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "findings": findings,
        "findings_count": len(findings),
    }


@router.post("/analyze")
def trigger_analysis(body: AnalyzeRequest = None, db: Session = Depends(get_db)):
    """
    저장된 스캔 결과에 대해 Gemini LLM 교차 검증을 실행하고
    배포 게이트 결과를 반환합니다.

    phase=1: SAST/SCA/IaC만 분석 (Docker 빌드 전 게이트)
      - BLOCK → pipeline status='blocked'
      - ALLOW/REVIEW → pipeline status='scanning_phase2' (DAST 진행)

    phase=2 (기본값): 모든 카테고리 분석 (최종 배포 게이트)
      - Phase 1 CrossValidation 결과 재사용 + DAST 새로 분석
      - Pipeline 최종 확정
    """
    from backend.app.models.tool_result import ToolResult
    from backend.app.models.scan import Scan
    from backend.app.models.pipeline_run import PipelineRun
    from backend.app.models.cross_validation import CrossValidation
    from backend.app.services import report_service

    phase = (body.phase if body and body.phase in (1, 2) else 2)
    commit_hash = (body.commit_hash if body else None)

    # commit_hash 없으면 최신 스캔 기준
    if not commit_hash:
        latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
        commit_hash = latest_scan.commit_hash if latest_scan else None

    # Phase별 새로 분석할 카테고리
    CATEGORY_TOOLS = {
        "SAST": {"sonarqube", "semgrep"},
        "SCA":  {"trivy", "depcheck"},
        "IaC":  {"tfsec", "checkov"},
        "DAST": {"zap"},
    }
    new_categories = {"DAST"} if phase == 2 else {"SAST", "SCA", "IaC"}
    allowed_tools = set()
    for cat in new_categories:
        allowed_tools |= CATEGORY_TOOLS.get(cat, set())

    # Pipeline 조회
    pipeline = None
    if commit_hash:
        pipeline = (
            db.query(PipelineRun)
            .filter(PipelineRun.commit_hash == commit_hash)
            .first()
        )

    pipeline_info = {
        "project_name": pipeline.project_name if pipeline else "secureflow",
        "commit_hash": commit_hash,
        "pipeline_id": pipeline.id if pipeline else None,
    }

    # Phase 2: Phase 1 CrossValidation 결과 재사용
    phase1_scored_pairs: list[dict] = []
    if phase == 2:
        prev_cv = (
            db.query(CrossValidation)
            .filter(
                CrossValidation.commit_hash == commit_hash,
                CrossValidation.phase == 1,
            )
            .order_by(CrossValidation.id.desc())
            .first()
        )
        if prev_cv and prev_cv.raw_report:
            phase1_scored_pairs = prev_cv.raw_report.get("findings", [])

    # ToolResult에서 해당 커밋 + 허용 도구 결과 수집
    all_results = db.query(ToolResult).order_by(ToolResult.id.desc()).all()
    latest_by_tool: dict[str, dict] = {}
    for tr in all_results:
        if (
            tr.name in allowed_tools
            and tr.name not in latest_by_tool
            and isinstance(tr.data, dict)
            and "parsed" in tr.data
        ):
            if commit_hash and tr.data.get("commit_hash") != commit_hash:
                continue
            latest_by_tool[tr.name] = tr.data["parsed"]

    if not latest_by_tool and not phase1_scored_pairs:
        raise HTTPException(
            status_code=404,
            detail="분석할 스캔 결과가 없습니다. 먼저 POST /api/v1/scans 로 스캔 결과를 제출하세요.",
        )

    # 교차 매칭 + 룰 기반 판정 (LLM은 CI에서 처리, 여기서는 호출 안 함)
    new_scored_pairs: list[dict] = []
    if latest_by_tool:
        tool_results = list(latest_by_tool.values())
        matched_pairs = scan_service.match_findings(tool_results)

        from engine.llm.prompts import _rule_based_fallback
        analyzed_pairs = _rule_based_fallback(matched_pairs)

        new_scored_pairs = scan_service.score_findings(analyzed_pairs)

    # Phase 1+2 합산 or Phase 1 단독
    all_scored_pairs = phase1_scored_pairs + new_scored_pairs if phase == 2 else new_scored_pairs

    # 게이트 결정
    gate = scan_service.get_gate_decision(all_scored_pairs)
    total_score = round(sum(p.get("row_score", 0.0) for p in all_scored_pairs), 2)

    # 요약 통계
    summary = {
        "total_findings": len(all_scored_pairs),
        "true_positive": sum(1 for p in all_scored_pairs if p.get("judgement_code") == "TRUE_POSITIVE"),
        "review_needed": sum(1 for p in all_scored_pairs if p.get("judgement_code") == "REVIEW_NEEDED"),
        "false_positive": sum(1 for p in all_scored_pairs if p.get("judgement_code") == "FALSE_POSITIVE"),
        "by_severity": {
            sev: sum(1 for p in all_scored_pairs if p.get("severity") == sev)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "phase": phase,
    }

    # 대시보드 리포트 생성
    dashboard = report_service.generate_dashboard_report(all_scored_pairs, pipeline_info)
    dashboard["total_score"] = total_score
    dashboard["summary"] = summary
    dashboard["gate_decision"] = gate
    dashboard["phase"] = phase
    dashboard["findings"] = all_scored_pairs  # Phase 2에서 재사용

    # Pipeline 상태 업데이트
    if pipeline:
        if phase == 1:
            if gate == "BLOCK":
                pipeline.status = "blocked"
            else:
                pipeline.status = "scanning_phase2"  # DAST 진행
            pipeline.gate_result = gate
            pipeline.gate_score = total_score
        else:
            # Phase 2 최종
            pipeline.gate_result = gate
            pipeline.gate_score = total_score
            pipeline.status = "blocked" if gate == "BLOCK" else "completed"

    # DB 저장
    report_record = ToolResult(name="report", status="ok", data=dashboard)
    db.add(report_record)

    cv = CrossValidation(
        project_name=pipeline_info["project_name"],
        commit_hash=commit_hash,
        phase=phase,
        gate_result=gate,
        gate_score=total_score,
        raw_report=dashboard,
    )
    db.add(cv)
    db.commit()

    return dashboard


# ── CI LLM Gate 결과 수신 ──────────────────────────────────────────────

class GateResultRequest(BaseModel):
    stage: str  # sast | sca | iac | dast
    commit_hash: str
    gate_result: dict  # run_llm_gate.py의 전체 JSON 출력

@router.post("/gate-result")
def receive_gate_result(body: GateResultRequest, db: Session = Depends(get_db)):
    """CI의 run_llm_gate.py 결과를 저장합니다."""
    from backend.app.models.scan import ToolResult

    record = ToolResult(
        name=f"llm-gate-{body.stage}",
        status="ok",
        data={
            "stage": body.stage,
            "commit_hash": body.commit_hash,
            **body.gate_result,
        },
    )
    db.add(record)
    db.commit()

    return {"status": "ok", "stage": body.stage, "id": record.id}
