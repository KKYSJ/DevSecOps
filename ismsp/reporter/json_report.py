"""
ISMS-P 평가 결과 JSON 보고서 생성 모듈

평가 결과를 대시보드 또는 API 응답에 적합한 구조화된 JSON으로 변환합니다.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# 심각도 우선순위 (정렬용)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _severity_key(item: dict) -> int:
    return _SEVERITY_ORDER.get(item.get("severity", "LOW"), 99)


def generate(evaluation_result: dict) -> dict:
    """
    평가 결과를 대시보드용 JSON 보고서로 변환합니다.

    Parameters
    ----------
    evaluation_result : dict
        evaluator.evaluate()가 반환한 평가 결과

    Returns
    -------
    dict
        구조화된 ISMS-P 점검 보고서
    """
    now_kst = datetime.now(timezone.utc).astimezone(
        # KST = UTC+9 (Python 3.9 이하에서 ZoneInfo 없이 처리)
        timezone.utc
    )
    generated_at = now_kst.strftime("%Y-%m-%dT%H:%M:%SZ")

    items = evaluation_result.get("items", [])

    # 심각도별 실패 항목 분류
    critical_failures = sorted(
        [i for i in items if i["status"] == "FAIL" and i.get("severity") in ("CRITICAL", "HIGH")],
        key=_severity_key,
    )

    # 전체 실패 항목 (심각도 순 정렬)
    all_failures = sorted(
        [i for i in items if i["status"] == "FAIL"],
        key=_severity_key,
    )

    # 통과 항목
    passed_items = [i for i in items if i["status"] == "PASS"]

    # 서비스별 집계
    service_summary: dict[str, dict] = {}
    for item in items:
        svc = item.get("isms_p_name", "기타")
        if svc not in service_summary:
            service_summary[svc] = {"total": 0, "passed": 0, "failed": 0, "na": 0}
        service_summary[svc]["total"] += 1
        status = item["status"]
        if status == "PASS":
            service_summary[svc]["passed"] += 1
        elif status == "FAIL":
            service_summary[svc]["failed"] += 1
        else:
            service_summary[svc]["na"] += 1

    # 심각도별 집계
    severity_summary: dict[str, dict] = {}
    for item in items:
        sev = item.get("severity", "MEDIUM")
        if sev not in severity_summary:
            severity_summary[sev] = {"total": 0, "passed": 0, "failed": 0}
        severity_summary[sev]["total"] += 1
        if item["status"] == "PASS":
            severity_summary[sev]["passed"] += 1
        elif item["status"] == "FAIL":
            severity_summary[sev]["failed"] += 1

    report = {
        "report_type": "isms_p",
        "standard": "ISMS-P (정보보호 및 개인정보보호 관리체계)",
        "generated_at": generated_at,
        "metadata": {
            "auto_check_items": evaluation_result.get("total", 0),
            "manual_check_items": 64,
            "total_isms_p_items": 102,
            "disclaimer": (
                "본 보고서는 ISMS-P 102개 통제 항목 중 AWS API로 자동 점검 가능한 "
                f"{evaluation_result.get('total', 0)}개 기술 항목의 점검 결과입니다. "
                "나머지 64개 항목은 수동 검토가 필요합니다."
            ),
        },
        "summary": {
            "total":            evaluation_result.get("total", 0),
            "passed":           evaluation_result.get("passed", 0),
            "failed":           evaluation_result.get("failed", 0),
            "na":               evaluation_result.get("na", 0),
            "error":            evaluation_result.get("error", 0),
            "pass_rate":        evaluation_result.get("pass_rate", 0.0),
            "critical_failures": [
                {
                    "id":          item["id"],
                    "isms_p_id":   item["isms_p_id"],
                    "isms_p_name": item["isms_p_name"],
                    "title":       item["title"],
                    "severity":    item["severity"],
                    "evidence":    item["evidence"],
                    "remediation": item["remediation"],
                }
                for item in critical_failures
            ],
        },
        "severity_breakdown": severity_summary,
        "category_breakdown": evaluation_result.get("by_category", {}),
        "service_breakdown": service_summary,
        "items": [
            {
                "id":           item["id"],
                "isms_p_id":    item["isms_p_id"],
                "isms_p_name":  item["isms_p_name"],
                "title":        item["title"],
                "status":       item["status"],
                "severity":     item["severity"],
                "evidence":     item["evidence"],
                "remediation":  item.get("remediation", ""),
                "details":      item.get("details", {}),
            }
            for item in items
        ],
        "failures": [
            {
                "id":          item["id"],
                "isms_p_id":   item["isms_p_id"],
                "isms_p_name": item["isms_p_name"],
                "title":       item["title"],
                "severity":    item["severity"],
                "evidence":    item["evidence"],
                "remediation": item["remediation"],
            }
            for item in all_failures
        ],
        "by_category": evaluation_result.get("by_category", {}),
    }

    logger.info(
        "JSON 보고서 생성 완료: 총 %d개 항목, 통과 %d개, 실패 %d개 (통과율 %.1f%%)",
        report["summary"]["total"],
        report["summary"]["passed"],
        report["summary"]["failed"],
        report["summary"]["pass_rate"],
    )

    return report


def to_json_string(report: dict, indent: int = 2) -> str:
    """보고서 딕셔너리를 JSON 문자열로 직렬화합니다."""
    return json.dumps(report, ensure_ascii=False, indent=indent, default=str)


def save(report: dict, output_path: str) -> str:
    """보고서를 JSON 파일로 저장합니다."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(to_json_string(report))
    logger.info("JSON 보고서가 저장되었습니다: %s", output_path)
    return output_path
