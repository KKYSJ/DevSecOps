"""
evaluator.py
─────────────
역할: 매핑 테이블 로드 + 수집 결과 대조 → 충족/미충족 판정

aws_checker.py가 수집한 CheckResult 리스트를 받아
ISMS-P 항목 단위로 집계하고 최종 판정을 내립니다.

판정 규칙:
    하나라도 NON_COMPLIANT   → 전체 NON_COMPLIANT
    모두 COMPLIANT           → COMPLIANT
    결과 없음 / 일부 INSUFF  → INSUFFICIENT_DATA
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import AUTOMATABLE_MAPPING, MANUAL_MAPPING
from .aws_checker import AWSChecker, CheckResult, ComplianceStatus

logger = logging.getLogger(__name__)


@dataclass
class ItemResult:
    """ISMS-P 항목 단위 최종 판정 결과."""
    isms_p_id       : str
    isms_p_name     : str
    automation_level: str               # "full" | "partial"
    status          : ComplianceStatus
    source          : str               # 판정에 기여한 주 소스
    check_results   : list[CheckResult] = field(default_factory=list)
    manual_supplement: Optional[str]   = None
    error           : Optional[str]    = None


class Evaluator:
    """
    ISMS-P 컴플라이언스 자동 판정 엔진.

    사용법:
        session  = boto3.Session(profile_name="my-profile")
        checker  = AWSChecker(session, region="ap-northeast-2")
        evaluator = Evaluator(checker)
        report   = evaluator.run()
    """

    def __init__(self, checker: AWSChecker):
        self.checker = checker
        self._automatable: list[dict] = []
        self._manual: list[dict] = []

    # ── Public ────────────────────────────────────────────────────────────────

    def load_mappings(self) -> None:
        """isms_p_automatable.json + isms_p_manual.json 로드."""
        with open(AUTOMATABLE_MAPPING, encoding="utf-8") as f:
            self._automatable = json.load(f)["requirements"]

        with open(MANUAL_MAPPING, encoding="utf-8") as f:
            self._manual = json.load(f)["requirements"]

        logger.info(
            f"[Evaluator] 매핑 로드 완료 — 자동화: {len(self._automatable)}개, "
            f"수동: {len(self._manual)}개"
        )

    def run(self, item_ids: list[str] | None = None) -> dict:
        """
        전체(또는 지정 항목) 평가 실행.

        Args:
            item_ids: 평가할 ISMS-P ID 목록. None이면 27개 전체.

        Returns:
            {metadata, summary, automated_results, manual_items}
        """
        if not self._automatable:
            self.load_mappings()

        targets = (
            [r for r in self._automatable if r["isms_p_id"] in item_ids]
            if item_ids else self._automatable
        )

        logger.info(f"[Evaluator] 평가 시작: {len(targets)}개 항목")

        automated_results: list[ItemResult] = []
        for item in targets:
            result = self._evaluate_item(item)
            automated_results.append(result)

        return {
            "metadata": self._build_metadata(),
            "summary":  self._build_summary(automated_results),
            "automated_results": [self._to_dict(r) for r in automated_results],
            "manual_items": [
                {
                    "isms_p_id":   m["isms_p_id"],
                    "isms_p_name": m["isms_p_name"],
                    "domain":      m.get("domain", ""),
                    "gate_fail":   m.get("gate_fail", ""),
                    "fail_reason": m.get("fail_reason", ""),
                    "status":      "MANUAL_REQUIRED",
                }
                for m in self._manual
            ],
        }

    # ── 항목 단위 평가 ─────────────────────────────────────────────────────────

    def _evaluate_item(self, item: dict) -> ItemResult:
        isms_p_id = item["isms_p_id"]
        try:
            check_results = self.checker.collect(
                isms_p_id=isms_p_id,
                aws_config_rules=item.get("aws_config_rules", []),
                security_hub_controls=item.get("security_hub_controls", []),
            )
            status = self._aggregate(check_results)
            source = self._primary_source(check_results)

        except Exception as e:
            logger.error(f"[Evaluator] {isms_p_id} 평가 오류: {e}")
            check_results = []
            status = ComplianceStatus.INSUFFICIENT_DATA
            source = "error"

        result = ItemResult(
            isms_p_id=isms_p_id,
            isms_p_name=item["isms_p_name"],
            automation_level=item.get("automation_level", "partial"),
            status=status,
            source=source,
            check_results=check_results,
            manual_supplement=item.get("manual_supplement"),
            error=None,
        )
        logger.info(
            f"[Evaluator] {isms_p_id} {item['isms_p_name']}: "
            f"{status.value} (소스: {source})"
        )
        return result

    # ── 집계 로직 ──────────────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(results: list[CheckResult]) -> ComplianceStatus:
        """
        판정 규칙:
            결과 없음                      → INSUFFICIENT_DATA
            하나라도 NON_COMPLIANT         → NON_COMPLIANT
            모두 COMPLIANT/NOT_APPLICABLE  → COMPLIANT
            나머지                         → INSUFFICIENT_DATA
        """
        if not results:
            return ComplianceStatus.INSUFFICIENT_DATA

        statuses = {r.status for r in results}

        if ComplianceStatus.NON_COMPLIANT in statuses:
            return ComplianceStatus.NON_COMPLIANT

        if all(s in (ComplianceStatus.COMPLIANT, ComplianceStatus.NOT_APPLICABLE)
               for s in statuses):
            return ComplianceStatus.COMPLIANT

        return ComplianceStatus.INSUFFICIENT_DATA

    @staticmethod
    def _primary_source(results: list[CheckResult]) -> str:
        sources = {r.source for r in results}
        for preferred in ("security_hub", "config_rule", "boto3_direct"):
            if preferred in sources:
                return preferred
        return "none"

    # ── 결과 직렬화 ────────────────────────────────────────────────────────────

    def _build_metadata(self) -> dict:
        try:
            account = self.checker.session.client("sts").get_caller_identity()["Account"]
        except Exception:
            account = "unknown"
        return {
            "title":      "ISMS-P 자동화 점검 결과",
            "standard":   "KISA ISMS-P 2023",
            "aws_account": account,
            "region":     self.checker.region,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _build_summary(results: list[ItemResult]) -> dict:
        compliant   = sum(1 for r in results if r.status == ComplianceStatus.COMPLIANT)
        non_comp    = sum(1 for r in results if r.status == ComplianceStatus.NON_COMPLIANT)
        insuff      = sum(1 for r in results if r.status == ComplianceStatus.INSUFFICIENT_DATA)
        total       = len(results)
        rate        = round(compliant / total * 100, 1) if total else 0
        return {
            "total_automated": total,
            "compliant":       compliant,
            "non_compliant":   non_comp,
            "insufficient_data": insuff,
            "compliance_rate_pct": rate,
        }

    @staticmethod
    def _to_dict(r: ItemResult) -> dict:
        return {
            "isms_p_id":        r.isms_p_id,
            "isms_p_name":      r.isms_p_name,
            "automation_level": r.automation_level,
            "status":           r.status.value,
            "source":           r.source,
            "manual_supplement": r.manual_supplement,
            "check_details": [
                {
                    "check_id": c.check_id,
                    "status":   c.status.value,
                    "source":   c.source,
                    "reason":   c.reason,
                }
                for c in r.check_results
            ],
            "error": r.error,
        }
