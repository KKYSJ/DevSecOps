"""
evaluator.py
─────────────
역할: 매핑 테이블 로드 + 수집 결과 대조 → 충족/미충족 판정

변경 이력:
    v2 — 대시보드 연동 구조로 출력 개편
         - automated_results + manual_items 분리 → items 단일 배열로 통합
         - 각 항목에 domain, subdomain, reason, checked_at 추가
         - boto3 전용 7개 항목에 boto3_check_ids 명시적 전달 (버그 수정)

출력 구조 (GET /isms 응답과 1:1 대응):
    {
      metadata: { aws_account, region, checked_at, ... },
      summary:  { total, compliant, non_compliant, insufficient_data,
                  manual_required, compliance_rate_pct },
      items: [                          ← 101개 통합 배열
        {
          isms_p_id, isms_p_name,
          domain, subdomain,            ← 영역별 필터용
          status,                       ← COMPLIANT/NON_COMPLIANT/INSUFFICIENT_DATA/MANUAL_REQUIRED
          automation_level,             ← full/partial/manual
          source,                       ← security_hub/config_rule/boto3_direct/manual/none
          reason,                       ← 미준수 이유 최상위 노출 (테이블 직접 표시용)
          manual_supplement,            ← 수동 보완 필요 사항
          checked_at,                   ← 항목별 점검 시각
          check_details: [...]          ← 세부 체크 결과 (상세 페이지용)
        }
      ]
    }

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
from typing import Optional

from ..config import AUTOMATABLE_MAPPING, MANUAL_MAPPING
from .aws_checker import AWSChecker, CheckResult, ComplianceStatus

logger = logging.getLogger(__name__)


# ── boto3 전용 항목 + Config Rule 미배포 대체 항목 ──────────────────────────
# Security Hub UNKNOWN + Config Rule 미배포인 경우 boto3로 직접 체크
_BOTO3_ONLY_CHECKS: dict[str, list[str]] = {
    # ── 원래 boto3 전용 7개 (aws_config_rules 자체가 없음) ──
    "2.1.3":  ["organizations_tags_policies_enabled_and_attached", "rds_instance_copy_tags_to_snapshots"],
    "2.5.2":  ["efs_access_point_enforce_user_identity"],
    "2.8.5":  ["codeartifact_packages_external_public_publishing_disabled"],
    "2.10.9": ["guardduty_ec2_malware_protection_enabled"],
    "2.11.1": ["iam_support_role_created", "ssmincidents_enabled_with_plans"],
    "2.11.2": ["inspector2_is_enabled", "ecr_registry_scan_images_on_push_enabled", "ecr_repositories_scan_vulnerabilities_in_latest_image"],
    "2.12.2": ["drs_job_exist"],
    # ── Config Rule 미배포 대체 ──
    "2.5.1":  ["iam-user-unused-credentials-check", "iam-policy-no-statements-with-admin-access"],
    "2.5.3":  ["iam-user-mfa-enabled", "root-account-mfa-enabled"],
    "2.5.4":  ["iam-password-policy"],
    "2.5.5":  ["iam-root-access-key-check"],
    "2.5.6":  ["access-keys-rotated"],
    "2.6.1":  ["restricted-ssh", "vpc-default-security-group-closed", "ec2-instances-in-vpc"],
    "2.6.2":  ["ec2-instance-no-public-ip", "rds-instance-public-access-check", "ebs-snapshot-public-restorable-check"],
    "2.6.3":  ["lambda-function-public-access-prohibited"],
    "2.6.4":  ["rds-instance-public-access-check", "rds-snapshots-public-prohibited"],
    "2.6.6":  ["restricted-ssh", "ec2-instances-in-vpc"],
    "2.7.1":  ["ec2-ebs-encryption-by-default", "s3-bucket-server-side-encryption-enabled", "rds-storage-encrypted", "elb-tls-https-listeners-only", "acm-certificate-expiration-check"],
    "2.7.2":  ["cmk-backing-key-rotation-enabled", "kms-cmk-not-scheduled-for-deletion"],
    "2.9.2":  ["cloudwatch-alarm-action-check", "ec2-instance-detailed-monitoring-enabled", "rds-enhanced-monitoring-enabled"],
    "2.9.3":  ["db-instance-backup-enabled", "s3-bucket-versioning-enabled"],
    "2.9.4":  ["cloudtrail-enabled", "cloud-trail-cloud-watch-logs-enabled", "cw-loggroup-retention-period-check"],
    "2.10.1": ["guardduty-enabled-centralized", "securityhub-enabled"],
    "2.10.2": ["s3-account-level-public-access-blocks-periodic", "ec2-ebs-encryption-by-default"],
    "2.10.8": ["ec2-managedinstance-patch-compliance-status-check"],
    "2.11.3": ["cloudwatch-alarm-action-check"],
    "2.12.1": ["rds-multi-az-support", "s3-bucket-replication-enabled"],
}


@dataclass
class ItemResult:
    """ISMS-P 항목 단위 최종 판정 결과."""
    isms_p_id        : str
    isms_p_name      : str
    domain           : str
    subdomain        : str
    automation_level : str                # "full" | "partial" | "manual"
    status           : ComplianceStatus
    source           : str
    reason           : Optional[str]      # 미준수/데이터부족 이유 최상위 노출
    checked_at       : str                # ISO 8601
    check_results    : list[CheckResult] = field(default_factory=list)
    manual_supplement: Optional[str]     = None
    error            : Optional[str]     = None


class Evaluator:
    """
    ISMS-P 컴플라이언스 자동 판정 엔진.

    사용법:
        checker   = AWSChecker(boto3_session, region="ap-northeast-2")
        evaluator = Evaluator(checker)
        report    = evaluator.run()
    """

    def __init__(self, checker: AWSChecker):
        self.checker = checker
        self._automatable: list[dict] = []
        self._manual: list[dict] = []

    def load_mappings(self) -> None:
        with open(AUTOMATABLE_MAPPING, encoding="utf-8") as f:
            self._automatable = json.load(f)["requirements"]
        with open(MANUAL_MAPPING, encoding="utf-8") as f:
            self._manual = json.load(f)["requirements"]
        logger.info(
            f"[Evaluator] 매핑 로드 — 자동화: {len(self._automatable)}개, "
            f"수동: {len(self._manual)}개"
        )

    def run(self, item_ids: list[str] | None = None) -> dict:
        if not self._automatable:
            self.load_mappings()

        targets = (
            [r for r in self._automatable if r["isms_p_id"] in item_ids]
            if item_ids else self._automatable
        )

        logger.info(f"[Evaluator] 평가 시작: 자동화 {len(targets)}개")

        automated_results: list[ItemResult] = []
        for item in targets:
            automated_results.append(self._evaluate_item(item))

        # 수동 항목은 item_ids 필터 없이 항상 전체 포함
        manual_results: list[ItemResult] = [
            self._make_manual_item(m) for m in self._manual
        ]

        # isms_p_id 기준 정렬해서 단일 배열로 통합
        all_items = sorted(
            automated_results + manual_results,
            key=lambda r: r.isms_p_id
        )

        return {
            "metadata": self._build_metadata(),
            "summary":  self._build_summary(automated_results, len(manual_results)),
            "items":    [self._to_dict(r) for r in all_items],
        }

    # ── 항목 단위 평가 ─────────────────────────────────────────────────────────

    def _evaluate_item(self, item: dict) -> ItemResult:
        isms_p_id  = item["isms_p_id"]
        checked_at = datetime.now(timezone.utc).isoformat()

        try:
            check_results = self.checker.collect(
                isms_p_id=isms_p_id,
                aws_config_rules=item.get("aws_config_rules", []),
                security_hub_controls=item.get("security_hub_controls", []),
                boto3_check_ids=_BOTO3_ONLY_CHECKS.get(isms_p_id),  # 7개 항목에만 전달
            )
            status = self._aggregate(check_results)
            source = self._primary_source(check_results)
            reason = self._extract_reason(check_results, status)

        except Exception as e:
            logger.error(f"[Evaluator] {isms_p_id} 평가 오류: {e}")
            check_results = []
            status = ComplianceStatus.INSUFFICIENT_DATA
            source = "error"
            reason = str(e)

        result = ItemResult(
            isms_p_id=isms_p_id,
            isms_p_name=item["isms_p_name"],
            domain=item.get("domain", ""),
            subdomain=item.get("subdomain", ""),
            automation_level=item.get("automation_level", "partial"),
            status=status,
            source=source,
            reason=reason,
            checked_at=checked_at,
            check_results=check_results,
            manual_supplement=item.get("manual_supplement"),
        )
        logger.info(
            f"[Evaluator] {isms_p_id} {item['isms_p_name']}: {status.value}"
            + (f" → {reason}" if reason else "")
        )
        return result

    def _make_manual_item(self, item: dict) -> ItemResult:
        """수동 항목 — MANUAL_REQUIRED 고정."""
        return ItemResult(
            isms_p_id=item["isms_p_id"],
            isms_p_name=item["isms_p_name"],
            domain=item.get("domain", ""),
            subdomain=item.get("subdomain", ""),
            automation_level="manual",
            status=ComplianceStatus.INSUFFICIENT_DATA,  # _to_dict에서 MANUAL_REQUIRED로 변환
            source="manual",
            reason=item.get("fail_reason", ""),
            checked_at="",
            manual_supplement="담당자가 직접 증빙 자료 확인 필요",
        )

    # ── 집계 로직 ──────────────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(results: list[CheckResult]) -> ComplianceStatus:
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
    def _extract_reason(
        results: list[CheckResult], status: ComplianceStatus
    ) -> Optional[str]:
        """미준수/데이터부족 이유를 최상위로 끌어올림 — 대시보드 테이블 직접 표시용."""
        if status == ComplianceStatus.COMPLIANT:
            return None
        if status == ComplianceStatus.NON_COMPLIANT:
            reasons = [
                f"{r.check_id}: {r.reason}"
                for r in results
                if r.status == ComplianceStatus.NON_COMPLIANT and r.reason
            ]
            return " | ".join(reasons) if reasons else "미준수"
        # INSUFFICIENT_DATA
        if not results:
            return "수집 결과 없음 — Security Hub/Config 활성화 필요"
        reasons = [
            r.reason for r in results
            if r.status == ComplianceStatus.INSUFFICIENT_DATA and r.reason
        ]
        return reasons[0] if reasons else "데이터 부족"

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
    def _build_summary(automated: list[ItemResult], manual_count: int) -> dict:
        compliant  = sum(1 for r in automated if r.status == ComplianceStatus.COMPLIANT)
        non_comp   = sum(1 for r in automated if r.status == ComplianceStatus.NON_COMPLIANT)
        insuff     = sum(1 for r in automated if r.status == ComplianceStatus.INSUFFICIENT_DATA)
        total_auto = len(automated)
        rate       = round(compliant / total_auto * 100, 1) if total_auto else 0.0
        return {
            "total":               total_auto + manual_count,
            "compliant":           compliant,
            "non_compliant":       non_comp,
            "insufficient_data":   insuff,
            "manual_required":     manual_count,
            "compliance_rate_pct": rate,
        }

    @staticmethod
    def _to_dict(r: ItemResult) -> dict:
        # 수동 항목은 MANUAL_REQUIRED로 표시
        status_val = "MANUAL_REQUIRED" if r.source == "manual" else r.status.value
        return {
            "isms_p_id":         r.isms_p_id,
            "isms_p_name":       r.isms_p_name,
            "domain":            r.domain,
            "subdomain":         r.subdomain,
            "automation_level":  r.automation_level,
            "status":            status_val,
            "source":            r.source,
            "reason":            r.reason,
            "manual_supplement": r.manual_supplement,
            "checked_at":        r.checked_at,
            "check_details": [
                {
                    "check_id": c.check_id,
                    "status":   c.status.value,
                    "source":   c.source,
                    "reason":   c.reason,
                }
                for c in r.check_results
            ],
        }
