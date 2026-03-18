"""
스캔 제출 및 조회 엔드포인트
"""

from typing import Any, Optional, Literal
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.services import scan_service

router = APIRouter()
logger = logging.getLogger(__name__)

_TOOL_CATEGORY = {
    "sonarqube": "SAST",
    "semgrep": "SAST",
    "trivy": "SCA",
    "depcheck": "SCA",
    "tfsec": "IaC",
    "checkov": "IaC",
    "zap": "DAST",
}


class ScanSubmitRequest(BaseModel):
    tool: str           # sonarqube | semgrep | trivy | depcheck | tfsec | checkov | zap
    raw_result: Any
    commit_hash: str    # 필수 — 동일 커밋의 스캔들을 Pipeline으로 묶는 키
    project_name: Optional[str] = "secureflow"
    branch: Optional[str] = "main"


class AnalyzeRequest(BaseModel):
    commit_hash: Optional[str] = None
    phase: Literal[1, 2] = 2   # 1 = Phase1(SAST/SCA/IaC), 2 = Phase2(+DAST, 최종)


def _upsert_pipeline(db: Session, scan_id: int, body: ScanSubmitRequest, category: str):
    """commit_hash 기준으로 Pipeline row를 생성하거나 scan_id를 추가합니다."""
    from backend.app.models.pipeline_run import PipelineRun

    pipeline = (
        db.query(PipelineRun)
        .filter(PipelineRun.commit_hash == body.commit_hash)
        .first()
    )

    if pipeline:
        current_ids = list(pipeline.scan_ids or [])
        if scan_id not in current_ids:
            current_ids.append(scan_id)
        pipeline.scan_ids = current_ids

        if category == "DAST" and pipeline.status == "scanning_phase1":
            pipeline.status = "scanning_phase2"
    else:
        initial_status = "scanning_phase2" if category == "DAST" else "scanning_phase1"
        pipeline = PipelineRun(
            project_name=body.project_name or "secureflow",
            commit_hash=body.commit_hash,
            branch=body.branch or "main",
            status=initial_status,
            scan_ids=[scan_id],
        )
        db.add(pipeline)


def _extract_finding_list(parsed: Any) -> list[dict]:
    """
    parsed 결과에서 finding 리스트를 최대한 유연하게 추출합니다.
    ZAP parsed 구조가 프로젝트마다 조금 다를 수 있어 방어적으로 처리합니다.
    """
    if parsed is None:
        return []

    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]

    if not isinstance(parsed, dict):
        return []

    candidate_keys = [
        "findings",
        "results",
        "vulnerabilities",
        "alerts",
        "items",
        "data",
    ]

    for key in candidate_keys:
        value = parsed.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]

    # 단일 finding dict처럼 보이면 리스트로 감싸기
    if any(k in parsed for k in ("title", "name", "severity", "risk", "url", "endpoint", "cwe_id", "cve_id")):
        return [parsed]

    return []


def _normalize_severity(value: Any) -> str:
    if value is None:
        return "LOW"

    s = str(value).strip().upper()

    mapping = {
        "INFO": "LOW",
        "INFORMATIONAL": "LOW",
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "HIGH": "HIGH",
        "CRITICAL": "CRITICAL",
        "0": "LOW",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
        "4": "CRITICAL",
    }
    return mapping.get(s, "LOW")


def _build_dast_pairs_from_zap(parsed: Any) -> list[dict]:
    """
    DAST는 현재 ZAP 단일 도구일 수 있으므로,
    match_findings() 결과가 비었을 때 단일 finding을 분석 가능한 pair 형식으로 감쌉니다.
    """
    findings = _extract_finding_list(parsed)
    pairs: list[dict] = []

    for idx, finding in enumerate(findings, start=1):
        title = (
            finding.get("title")
            or finding.get("name")
            or finding.get("alert")
            or f"ZAP Finding {idx}"
        )
        severity = _normalize_severity(
            finding.get("severity")
            or finding.get("risk")
            or finding.get("riskcode")
        )
        description = (
            finding.get("description")
            or finding.get("message")
            or finding.get("desc")
            or ""
        )
        target = (
            finding.get("target_label")
            or finding.get("url")
            or finding.get("uri")
            or finding.get("endpoint")
            or finding.get("path")
            or title
        )

        pair = {
            "row_id": f"dast-zap-{idx}",
            "category": "DAST",
            "target_label": target,
            "tool_a": {
                "tool_name": "zap",
                "status": "detected",
                "display_result": f"{title}, {severity}",
                "finding": finding,
            },
            "tool_b": {
                "tool_name": None,
                "status": "not_applicable",
                "display_result": "DAST 단일 도구 분석",
                "finding": None,
            },
            "judgement_code": "REVIEW_NEEDED",
            "confidence": "MEDIUM",
            "severity": severity,
            "title": title,
            "description": description,
            "reason": description or "ZAP 단일 도구 결과를 기반으로 분석했습니다.",
        }
        pairs.append(pair)

    return pairs


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
    db.flush()

    _upsert_pipeline(db, scan.id, body, category)
    db.commit()
    db.refresh(scan)

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
def trigger_analysis(body: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    저장된 스캔 결과에 대해 Gemini LLM 교차 검증을 실행하고
    배포 게이트 결과를 반환합니다.

    phase=1: SAST/SCA/IaC만 분석
      - 취약점이 없어도 기존 프롬프트로 LLM 호출 수행
      - BLOCK → pipeline status='blocked'
      - ALLOW/REVIEW → pipeline status='scanning_phase2'

    phase=2: Phase 1 결과 재사용 + DAST 새로 분석
      - DAST 취약점이 없어도 기존 프롬프트로 LLM 호출 수행
      - 최종 배포 게이트 계산
    """
    from backend.app.models.tool_result import ToolResult
    from backend.app.models.scan import Scan
    from backend.app.models.pipeline_run import PipelineRun
    from backend.app.models.cross_validation import CrossValidation
    from backend.app.services import report_service

    phase = body.phase
    commit_hash = body.commit_hash

    if not commit_hash:
        latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
        commit_hash = latest_scan.commit_hash if latest_scan else None

    if not commit_hash:
        raise HTTPException(
            status_code=404,
            detail="분석할 commit_hash를 찾을 수 없습니다. 먼저 스캔 결과를 제출하세요.",
        )

    CATEGORY_TOOLS = {
        "SAST": {"sonarqube", "semgrep"},
        "SCA": {"trivy", "depcheck"},
        "IaC": {"tfsec", "checkov"},
        "DAST": {"zap"},
    }

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

        if not prev_cv or not prev_cv.raw_report:
            raise HTTPException(
                status_code=400,
                detail=f"Phase 2 분석 전에 동일 commit_hash({commit_hash})로 Phase 1 분석이 먼저 완료되어야 합니다.",
            )

        phase1_scored_pairs = prev_cv.raw_report.get("findings", [])

    new_categories = {"DAST"} if phase == 2 else {"SAST", "SCA", "IaC"}
    allowed_tools = set()
    for cat in new_categories:
        allowed_tools |= CATEGORY_TOOLS.get(cat, set())

    all_results = db.query(ToolResult).order_by(ToolResult.id.desc()).all()
    latest_by_tool: dict[str, Any] = {}

    for tr in all_results:
        if tr.name not in allowed_tools:
            continue
        if tr.name in latest_by_tool:
            continue
        if not isinstance(tr.data, dict):
            continue
        if "parsed" not in tr.data:
            continue
        if commit_hash and tr.data.get("commit_hash") != commit_hash:
            continue

        latest_by_tool[tr.name] = tr.data["parsed"]

    logger.info(
        "trigger_analysis phase=%s commit_hash=%s allowed_tools=%s collected_tools=%s",
        phase,
        commit_hash,
        sorted(list(allowed_tools)),
        sorted(list(latest_by_tool.keys())),
    )

    if phase == 1 and not latest_by_tool:
        raise HTTPException(
            status_code=404,
            detail="Phase 1에 필요한 SAST/SCA/IaC 스캔 결과가 없습니다.",
        )

    if phase == 2 and "zap" not in latest_by_tool:
        raise HTTPException(
            status_code=400,
            detail=f"Phase 2 분석을 위한 ZAP 결과가 없습니다. commit_hash={commit_hash}",
        )

    new_scored_pairs: list[dict] = []

    if latest_by_tool:
        matched_pairs: list[dict] = []

        if phase == 2:
            zap_parsed = latest_by_tool.get("zap")
            matched_pairs = scan_service.match_findings([zap_parsed]) if zap_parsed else []

            if not matched_pairs:
                matched_pairs = _build_dast_pairs_from_zap(zap_parsed)

            # phase=2에서는 더 이상 여기서 예외를 던지지 않고,
            # 빈 결과라도 기존 프롬프트를 호출하도록 아래에서 처리한다.
        else:
            tool_results = list(latest_by_tool.values())
            matched_pairs = scan_service.match_findings(tool_results)

        logger.info(
            "trigger_analysis phase=%s commit_hash=%s matched_pairs=%s",
            phase,
            commit_hash,
            len(matched_pairs),
        )

        try:
            from engine.llm.prompts import build_cross_validation_prompt, parse_llm_response
            from engine.llm.client import call_llm

            analyzed_pairs = list(matched_pairs)

            # 빈 결과여도 기존 프롬프트를 사용해 LLM 호출 수행
            if not matched_pairs:
                empty_categories = ["DAST"] if phase == 2 else ["SAST", "SCA", "IaC"]

                for category in empty_categories:
                    try:
                        prompt = build_cross_validation_prompt(category, [])
                        response = call_llm(prompt)
                        parsed_empty = parse_llm_response(response, [])

                        logger.info(
                            "empty llm called phase=%s category=%s parsed_count=%s",
                            phase,
                            category,
                            len(parsed_empty) if isinstance(parsed_empty, list) else 0,
                        )
                    except Exception as e:
                        logger.warning(
                            "빈 결과 LLM 호출 실패(phase=%s, category=%s): %s",
                            phase,
                            category,
                            e,
                        )

                # 빈 결과는 그대로 유지
                new_scored_pairs = []
            else:
                categories = list(dict.fromkeys(p["category"] for p in matched_pairs))

                for category in categories:
                    cat_indices = [i for i, p in enumerate(matched_pairs) if p["category"] == category]
                    cat_pairs = [matched_pairs[i] for i in cat_indices]

                    prompt = build_cross_validation_prompt(category, cat_pairs)
                    response = call_llm(prompt)
                    cat_analyzed = parse_llm_response(response, cat_pairs)

                    for list_idx, analyzed_pair in zip(cat_indices, cat_analyzed):
                        if analyzed_pair.get("confidence_level"):
                            analyzed_pair["confidence"] = analyzed_pair["confidence_level"]
                        analyzed_pairs[list_idx] = analyzed_pair

                new_scored_pairs = scan_service.score_findings(analyzed_pairs)

        except Exception as e:
            logger.exception("LLM 분석 실패, 기본 분석으로 폴백: %s", e)

            if matched_pairs:
                analyzed_pairs = scan_service.analyze_with_llm(matched_pairs)
                new_scored_pairs = scan_service.score_findings(analyzed_pairs)
            else:
                # phase=1, phase=2 모두 빈 결과면 정상 진행
                new_scored_pairs = []

    logger.info(
        "trigger_analysis phase=%s commit_hash=%s phase1_pairs=%s new_pairs=%s",
        phase,
        commit_hash,
        len(phase1_scored_pairs),
        len(new_scored_pairs),
    )

    all_scored_pairs = phase1_scored_pairs + new_scored_pairs if phase == 2 else new_scored_pairs

    gate = scan_service.get_gate_decision(all_scored_pairs)
    total_score = round(sum(p.get("row_score", 0.0) for p in all_scored_pairs), 2)

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

    dashboard = report_service.generate_dashboard_report(all_scored_pairs, pipeline_info)
    dashboard["total_score"] = total_score
    dashboard["summary"] = summary
    dashboard["gate_decision"] = gate
    dashboard["phase"] = phase
    dashboard["findings"] = all_scored_pairs

    if pipeline:
        if phase == 1:
            if gate == "BLOCK":
                pipeline.status = "blocked"
            else:
                pipeline.status = "scanning_phase2"
            pipeline.gate_result = gate
            pipeline.gate_score = total_score
        else:
            pipeline.gate_result = gate
            pipeline.gate_score = total_score
            pipeline.status = "blocked" if gate == "BLOCK" else "completed"

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