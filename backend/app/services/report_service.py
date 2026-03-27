"""
SecureFlow 리포트 생성 서비스
"""

import uuid
from datetime import datetime, timezone
from typing import Any


_STAGE_CATEGORY = {
    "sast": "SAST",
    "sca": "SCA",
    "iac": "IaC",
    "dast": "DAST",
    "image": "IMAGE",
}

_GATE_DECISION_MAP = {
    "allow": "ALLOW",
    "pass": "ALLOW",
    "review": "REVIEW",
    "warn": "REVIEW",
    "block": "BLOCK",
    "fail": "BLOCK",
}


def _normalize_gate_decision(decision: str | None) -> str | None:
    if not decision:
        return None
    return _GATE_DECISION_MAP.get(str(decision).strip().lower())


def _normalize_confidence(value: str | None) -> str:
    raw = str(value or "MED").strip().upper()
    if raw == "MEDIUM":
        return "MED"
    if raw in {"HIGH", "MED", "LOW"}:
        return raw
    return "MED"


def _normalize_judgment_item(stage: str, item: dict, index: int) -> dict:
    finding_a = item.get("finding_a")
    finding_b = item.get("finding_b")
    severity = (item.get("reassessed_severity") or item.get("severity") or "MEDIUM").upper()

    return {
        "category": _STAGE_CATEGORY.get(stage, stage.upper()),
        "tool_a": (finding_a or {}).get("tool"),
        "tool_b": (finding_b or {}).get("tool"),
        "correlation_key": item.get("correlation_key") or f"{stage}:{index}",
        "confidence": _normalize_confidence(item.get("confidence") or item.get("confidence_level")),
        "severity": severity,
        "judgement_code": item.get("judgement_code") or "REVIEW_NEEDED",
        "reason": item.get("reason") or item.get("risk_summary") or "",
        "action_text": item.get("action_text") or "",
        "finding_a": finding_a,
        "finding_b": finding_b,
        "title_ko": item.get("title_ko") or "",
        "risk_summary": item.get("risk_summary") or "",
        "reassessed_severity": severity,
    }


def generate_dashboard_report(scored_pairs: list[dict], pipeline_info: dict) -> dict:
    """
    스코어링된 쌍 목록과 파이프라인 정보로 대시보드 리포트 JSON 생성.

    Args:
        scored_pairs: scan_service.score_findings() 결과
        pipeline_info: 파이프라인 메타데이터 (commit_hash, project_name 등)

    Returns:
        대시보드 리포트 딕셔너리
    """
    from backend.app.services.scan_service import get_gate_decision

    gate_decision = get_gate_decision(scored_pairs)
    total_score = round(sum(p.get("row_score", 0.0) for p in scored_pairs), 2)

    # 카테고리별 섹션 구성
    sections: dict[str, list] = {"SAST": [], "SCA": [], "IaC": [], "DAST": []}
    for pair in scored_pairs:
        cat = pair.get("category", "SAST")
        sections.setdefault(cat, []).append({
            "correlation_key": pair.get("correlation_key", ""),
            "tool_a": pair.get("tool_a"),
            "tool_b": pair.get("tool_b"),
            "confidence": pair.get("confidence", "LOW"),
            "severity": pair.get("severity", "INFO"),
            "judgement_code": pair.get("judgement_code", "REVIEW_NEEDED"),
            "row_score": pair.get("row_score", 0.0),
            "reason": pair.get("reason", ""),
            "action_text": pair.get("action_text", ""),
            "finding_a": pair.get("finding_a"),
            "finding_b": pair.get("finding_b"),
        })

    # 심각도별 집계
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for pair in scored_pairs:
        sev = pair.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # 판정별 집계
    judgement_counts = {"TRUE_POSITIVE": 0, "REVIEW_NEEDED": 0, "FALSE_POSITIVE": 0}
    for pair in scored_pairs:
        jc = pair.get("judgement_code", "REVIEW_NEEDED")
        if jc in judgement_counts:
            judgement_counts[jc] += 1

    report_id = str(uuid.uuid4())

    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_name": pipeline_info.get("project_name", "secureflow"),
        "commit_hash": pipeline_info.get("commit_hash"),
        "gate_decision": gate_decision,
        "total_score": total_score,
        "summary": {
            "total_pairs": len(scored_pairs),
            "severity_counts": severity_counts,
            "judgement_counts": judgement_counts,
        },
        "sections": sections,
        "pipeline_info": pipeline_info,
    }


def _collect_scored_pairs(judgments: dict[str, list]) -> list[dict]:
    from backend.app.services.scan_service import score_findings

    normalized_pairs: list[dict] = []
    for stage, items in judgments.items():
        if stage not in _STAGE_CATEGORY or not isinstance(items, list):
            continue
        for index, item in enumerate(items):
            if isinstance(item, dict):
                normalized_pairs.append(_normalize_judgment_item(stage, item, index))

    return score_findings(normalized_pairs)


def _overall_gate_from_stage_gates(gates: dict[str, dict]) -> str | None:
    normalized = [
        _normalize_gate_decision((gate or {}).get("decision") or (gate or {}).get("gate_result"))
        for stage, gate in gates.items()
        if stage in _STAGE_CATEGORY
    ]
    filtered = [decision for decision in normalized if decision]
    if not filtered:
        return None
    if "BLOCK" in filtered:
        return "BLOCK"
    if "REVIEW" in filtered:
        return "REVIEW"
    return "ALLOW"


def build_report_from_judgments(
    *,
    commit_hash: str,
    project_name: str,
    judgments: dict[str, list],
    summaries: dict[str, dict] | None = None,
    gates: dict[str, dict] | None = None,
) -> dict | None:
    summaries = summaries or {}
    gates = gates or {}
    scored_pairs = _collect_scored_pairs(judgments)
    if not scored_pairs:
        return None

    pipeline_info = {
        "project_name": project_name or "secureflow",
        "commit_hash": commit_hash,
        "pipeline_id": None,
    }
    dashboard = generate_dashboard_report(scored_pairs, pipeline_info)

    total_score = round(sum(pair.get("row_score", 0.0) for pair in scored_pairs), 2)
    overall_gate = _overall_gate_from_stage_gates(gates) or dashboard.get("gate_decision", "ALLOW")
    phase = 2 if ("dast" in judgments or "dast" in gates) else 1

    dashboard["total_score"] = total_score
    dashboard["gate_decision"] = overall_gate
    dashboard["phase"] = phase
    dashboard["findings"] = scored_pairs
    dashboard["summary"] = {
        "total_findings": len(scored_pairs),
        "true_positive": sum(1 for pair in scored_pairs if pair.get("judgement_code") == "TRUE_POSITIVE"),
        "review_needed": sum(1 for pair in scored_pairs if pair.get("judgement_code") == "REVIEW_NEEDED"),
        "false_positive": sum(1 for pair in scored_pairs if pair.get("judgement_code") == "FALSE_POSITIVE"),
        "by_severity": {
            sev: sum(
                1
                for pair in scored_pairs
                if (pair.get("reassessed_severity") or pair.get("severity")) == sev
            )
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        },
        "stage_summaries": summaries,
        "phase": phase,
    }
    return dashboard


def refresh_report_from_llm(db: Any, commit_hash: str) -> dict | None:
    from backend.app.models.cross_validation import CrossValidation
    from backend.app.models.pipeline_run import PipelineRun
    from backend.app.models.tool_result import ToolResult

    if not commit_hash:
        return None

    records = (
        db.query(ToolResult)
        .filter(ToolResult.name.like("llm-gate-%"))
        .order_by(ToolResult.id.desc())
        .limit(100)
        .all()
    )

    gates: dict[str, dict] = {}
    judgments: dict[str, list] = {}
    summaries: dict[str, dict] = {}

    for record in records:
        data = record.data or {}
        if data.get("commit_hash") != commit_hash:
            continue

        stage = data.get("stage")
        if stage == "judgments":
            inner_judgments = data.get("judgments", {})
            if isinstance(inner_judgments, dict):
                for key, items in inner_judgments.items():
                    if key in _STAGE_CATEGORY and key not in judgments and isinstance(items, list) and items:
                        judgments[key] = items

            inner_summaries = data.get("summaries", {})
            if isinstance(inner_summaries, dict):
                for key, summary in inner_summaries.items():
                    if key in _STAGE_CATEGORY and key not in summaries and isinstance(summary, dict):
                        summaries[key] = summary
            continue

        if stage in _STAGE_CATEGORY and stage not in gates:
            gates[stage] = data

    dashboard = build_report_from_judgments(
        commit_hash=commit_hash,
        project_name="secureflow",
        judgments=judgments,
        summaries=summaries,
        gates=gates,
    )
    if not dashboard:
        return None

    pipeline = (
        db.query(PipelineRun)
        .filter(PipelineRun.commit_hash == commit_hash)
        .order_by(PipelineRun.id.desc())
        .first()
    )
    if pipeline:
        project_name = pipeline.project_name or dashboard["project_name"]
        dashboard["project_name"] = project_name
        dashboard["pipeline_info"]["project_name"] = project_name
        dashboard["pipeline_info"]["pipeline_id"] = pipeline.id
        pipeline.gate_result = dashboard["gate_decision"]
        pipeline.gate_score = dashboard["total_score"]
        if dashboard["gate_decision"] == "BLOCK":
            pipeline.status = "blocked"
        elif dashboard.get("phase") == 2:
            pipeline.status = "completed"
        else:
            pipeline.status = "scanning_phase2"

    report_record = ToolResult(name="report", status="ok", data=dashboard)
    db.add(report_record)

    cv = CrossValidation(
        project_name=dashboard.get("project_name", "secureflow"),
        commit_hash=commit_hash,
        phase=dashboard.get("phase", 1),
        gate_result=dashboard.get("gate_decision"),
        gate_score=dashboard.get("total_score"),
        raw_report=dashboard,
    )
    db.add(cv)
    db.commit()
    return dashboard


def list_reports(db: Any) -> list:
    """
    DB에서 저장된 리포트 목록 조회.
    실제 리포트는 ToolResult 테이블의 name='report' 레코드에 저장됨.

    Args:
        db: SQLAlchemy 세션

    Returns:
        리포트 메타데이터 리스트
    """
    from backend.app.models.tool_result import ToolResult

    try:
        records = (
            db.query(ToolResult)
            .filter(ToolResult.name == "report")
            .order_by(ToolResult.id.desc())
            .limit(50)
            .all()
        )
        reports = []
        for rec in records:
            data = rec.data or {}
            reports.append({
                "id": str(rec.id),
                "report_id": data.get("report_id", str(rec.id)),
                "generated_at": data.get("generated_at", ""),
                "project_name": data.get("project_name", "secureflow"),
                "commit_hash": data.get("commit_hash"),
                "gate_decision": data.get("gate_decision", "ALLOW"),
                "total_score": data.get("total_score", 0.0),
            })
        return reports
    except Exception:
        return []
