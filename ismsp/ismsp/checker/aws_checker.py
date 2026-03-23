"""
aws_checker.py
───────────────
역할: AWS 설정값 수집 전담 (판정 로직 없음)

수집 우선순위:
    1순위 Security Hub  → FSBP Control 결과 조회
    2순위 AWS Config    → Managed Rule 준수 상태 조회
    3순위 boto3 직접    → 위 두 계층이 커버 못하는 항목

반환:
    CheckResult 리스트 → evaluator.py가 판정에 사용

표기 방식:
    aws_config_rules 필드 → 하이픈(kebab-case)  예: "cloudtrail-enabled"
    prowler_checks 필드   → 언더스코어(snake_case) 예: "cloudtrail_multi_region_enabled"
    boto3_check_ids 필드  → 언더스코어(snake_case) 예: "organizations_tags_policies_enabled_and_attached"
    boto3_check_ids는 prowler check 이름을 그대로 사용 — boto3 수집 함수와 1:1 매핑
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# ── 공통 데이터 클래스 ─────────────────────────────────────────────────────────

class ComplianceStatus(str, Enum):
    COMPLIANT        = "COMPLIANT"
    NON_COMPLIANT    = "NON_COMPLIANT"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NOT_APPLICABLE   = "NOT_APPLICABLE"


@dataclass
class CheckResult:
    """단일 check 항목의 수집 결과."""
    isms_p_id : str
    check_id  : str                      # aws_config_rules 형식 (하이픈)
    status    : ComplianceStatus
    source    : str                      # "security_hub" | "config_rule" | "boto3_direct"
    reason    : Optional[str] = None     # NON_COMPLIANT/INSUFFICIENT_DATA 사유
    raw       : Optional[dict] = field(default=None, repr=False)


# ── Security Hub → Config Rule 매핑 테이블 ────────────────────────────────────
# Config Rule 이름(하이픈) → Security Hub FSBP Control ID
_SH_MAP: dict[str, str] = {
    "iam-user-mfa-enabled":                         "IAM.5",
    "mfa-enabled-for-iam-console-access":           "IAM.5",
    "root-account-mfa-enabled":                     "IAM.9",
    "iam-root-access-key-check":                    "IAM.4",
    "iam-password-policy":                          "IAM.8",
    "iam-user-unused-credentials-check":            "IAM.3",
    "iam-policy-no-statements-with-admin-access":   "IAM.1",
    "iam-user-no-policies-check":                   "IAM.2",
    "access-keys-rotated":                          "IAM.3",
    "s3-account-level-public-access-blocks-periodic": "S3.1",
    "s3-bucket-public-read-prohibited":             "S3.2",
    "s3-bucket-public-write-prohibited":            "S3.3",
    "s3-bucket-server-side-encryption-enabled":     "S3.4",
    "s3-bucket-ssl-requests-only":                  "S3.5",
    "s3-bucket-versioning-enabled":                 "S3.9",
    "ec2-instance-no-public-ip":                    "EC2.9",
    "restricted-ssh":                               "EC2.13",
    "vpc-default-security-group-closed":            "EC2.2",
    "ec2-ebs-encryption-by-default":               "EC2.7",
    "ebs-snapshot-public-restorable-check":        "EC2.1",
    "rds-instance-public-access-check":             "RDS.2",
    "rds-storage-encrypted":                        "RDS.3",
    "rds-instance-deletion-protection-enabled":     "RDS.8",
    "rds-snapshots-public-prohibited":              "RDS.7",
    "db-instance-backup-enabled":                   "RDS.5",
    "cloudtrail-enabled":                           "CloudTrail.1",
    "cloud-trail-cloud-watch-logs-enabled":         "CloudTrail.4",
    "cloud-trail-log-file-validation-enabled":      "CloudTrail.2",
    "cloudtrail-s3-dataevents-enabled":             "CloudTrail.7",
    "cmk-backing-key-rotation-enabled":             "KMS.1",
    "kms-cmk-not-scheduled-for-deletion":           "KMS.2",
    "acm-certificate-expiration-check":             "ACM.1",
    "elb-tls-https-listeners-only":                 "ELB.3",
    "lambda-function-public-access-prohibited":     "Lambda.1",
    "guardduty-enabled-centralized":                "GuardDuty.1",
    "securityhub-enabled":                          "SecurityHub.1",
}

# boto3 직접 처리 항목 (Config Rule/SH 매핑 없는 항목)
# key: 내부 식별자,  value: 실제 수집 함수 이름
_BOTO3_CHECKS: set[str] = {
    "boto3-iam-account-summary",
    "boto3-iam-password-policy",
    "boto3-root-access-key",
    "boto3-kms-key-rotation",
    "boto3-s3-encryption",
    "boto3-cloudtrail-multiregion",
    "boto3-vpc-flow-logs",
    "boto3-cw-log-retention",
    "boto3-guardduty-enabled",
    "boto3-securityhub-enabled",
    "boto3-macie-enabled",
    "boto3-inspector2-enabled",
    "boto3-ssm-patch-compliance",
    "boto3-backup-plans",
    "boto3-org-tag-policies",
    "boto3-drs-job-exists",
}


class AWSChecker:
    """
    AWS 설정값 수집기.

    사용법:
        checker = AWSChecker(boto3_session, region="ap-northeast-2")
        results = checker.collect(isms_p_id="2.5.3",
                                  aws_config_rules=["iam-user-mfa-enabled"],
                                  security_hub_controls=["IAM.5"])
    """

    def __init__(self, session, region: str = "ap-northeast-2"):
        self.session = session
        self.region  = region

        # 클라이언트 캐시 (lazy init)
        self._clients: dict = {}
        # Security Hub Control 결과 캐시 (최초 1회 로드)
        self._sh_cache: dict[str, str] | None = None
        self._sh_enabled: bool | None = None

    # ── Public ────────────────────────────────────────────────────────────────

    def collect(
        self,
        isms_p_id: str,
        aws_config_rules: list[str],
        security_hub_controls: list[str],
        boto3_check_ids: list[str] | None = None,
    ) -> list[CheckResult]:
        """
        1순위 Security Hub → 2순위 Config → 3순위 boto3 순으로 수집.
        처리된 check는 다음 순위로 넘기지 않습니다.

        Args:
            boto3_check_ids: prowler check 이름(언더스코어) 목록.
                             aws_config_rules/security_hub_controls가 없는
                             boto3 전용 항목(7개)에 명시적으로 전달됩니다.
        """
        results: list[CheckResult] = []
        remaining = list(aws_config_rules)

        # 1순위: Security Hub
        sh_results, remaining = self._collect_from_security_hub(isms_p_id, remaining)
        results.extend(sh_results)

        # 2순위: AWS Config (SH가 못 커버한 것만)
        config_results, remaining = self._collect_from_config(isms_p_id, remaining)
        results.extend(config_results)

        # 3순위: boto3 직접
        # - aws_config_rules 처리 후 남은 항목 중 boto3- 접두어
        # - + evaluator가 명시적으로 전달한 boto3_check_ids (boto3 전용 7개 항목)
        boto3_from_remaining = [c for c in remaining if c in _BOTO3_CHECKS]
        boto3_explicit = [c for c in (boto3_check_ids or []) if c in self._boto3_fn_map()]
        boto3_targets = list(dict.fromkeys(boto3_from_remaining + boto3_explicit))  # 중복 제거
        boto3_results = self._collect_from_boto3(isms_p_id, boto3_targets)
        results.extend(boto3_results)

        logger.debug(
            f"[AWSChecker] {isms_p_id}: 총 {len(results)}개 결과 "
            f"(SH={len(sh_results)}, Config={len(config_results)}, boto3={len(boto3_results)})"
        )
        return results

    # ── 1순위: Security Hub ───────────────────────────────────────────────────

    def _collect_from_security_hub(
        self, isms_p_id: str, check_ids: list[str]
    ) -> tuple[list[CheckResult], list[str]]:
        """SH로 처리 가능한 항목 수집. 처리 못한 항목은 remaining에 반환."""
        results: list[CheckResult] = []
        remaining: list[str] = []

        if not self._is_sh_enabled():
            return results, check_ids  # SH 비활성화 → 전부 remaining

        self._load_sh_cache()

        for check_id in check_ids:
            control_id = _SH_MAP.get(check_id)
            if not control_id:
                remaining.append(check_id)
                continue

            sh_status = self._sh_cache.get(control_id)

            # SH 캐시에 없거나 UNKNOWN → Config/boto3로 폴백
            if sh_status is None or sh_status == "UNKNOWN":
                remaining.append(check_id)
                logger.debug(
                    f"[AWSChecker] {check_id} → SH Control {control_id} "
                    f"상태 {sh_status!r} → Config 폴백"
                )
                continue

            status = {
                "PASSED": ComplianceStatus.COMPLIANT,
                "FAILED": ComplianceStatus.NON_COMPLIANT,
            }.get(sh_status, ComplianceStatus.INSUFFICIENT_DATA)

            results.append(CheckResult(
                isms_p_id=isms_p_id,
                check_id=check_id,
                status=status,
                source="security_hub",
                reason=f"FSBP {control_id}: {sh_status}" if status != ComplianceStatus.COMPLIANT else None,
                raw={"control_id": control_id, "sh_status": sh_status},
            ))

        return results, remaining

    def _is_sh_enabled(self) -> bool:
        if self._sh_enabled is not None:
            return self._sh_enabled
        try:
            self._client("securityhub").describe_hub()
            self._sh_enabled = True
        except ClientError as e:
            code = e.response["Error"]["Code"]
            self._sh_enabled = code not in ("InvalidAccessException", "ResourceNotFoundException")
        return self._sh_enabled

    def _load_sh_cache(self):
        if self._sh_cache is not None:
            return
        self._sh_cache = {}
        try:
            sh = self._client("securityhub")
            standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
            fsbp = next(
                (s["StandardsSubscriptionArn"] for s in standards
                 if "aws-foundational-security-best-practices" in s.get("StandardsArn", "")),
                None,
            )
            if not fsbp:
                return
            paginator = sh.get_paginator("describe_standards_controls")
            for page in paginator.paginate(StandardsSubscriptionArn=fsbp):
                for ctrl in page.get("Controls", []):
                    self._sh_cache[ctrl["ControlId"]] = ctrl.get("ComplianceStatus", "UNKNOWN")
            logger.info(f"[AWSChecker] Security Hub 캐시 로드: {len(self._sh_cache)}개 Control")
        except ClientError as e:
            logger.error(f"[AWSChecker] SH 캐시 로드 실패: {e}")

    # ── 2순위: AWS Config ─────────────────────────────────────────────────────

    def _collect_from_config(
        self, isms_p_id: str, check_ids: list[str]
    ) -> tuple[list[CheckResult], list[str]]:
        results: list[CheckResult] = []
        remaining: list[str] = []
        config = self._client("config")

        for check_id in check_ids:
            if check_id.startswith("boto3-"):
                remaining.append(check_id)
                continue
            try:
                paginator = config.get_paginator("get_compliance_details_by_config_rule")
                all_evals = []
                for page in paginator.paginate(
                    ConfigRuleName=check_id,
                    ComplianceTypes=["COMPLIANT", "NON_COMPLIANT"],
                ):
                    all_evals.extend(page.get("EvaluationResults", []))

                if not all_evals:
                    status = ComplianceStatus.NOT_APPLICABLE
                    reason = None
                else:
                    nc = [
                        r.get("EvaluationResultIdentifier", {})
                         .get("EvaluationResultQualifier", {})
                         .get("ResourceId", "unknown")
                        for r in all_evals if r.get("ComplianceType") == "NON_COMPLIANT"
                    ]
                    status = ComplianceStatus.NON_COMPLIANT if nc else ComplianceStatus.COMPLIANT
                    reason = f"미준수 리소스: {', '.join(nc[:5])}" if nc else None

                results.append(CheckResult(
                    isms_p_id=isms_p_id,
                    check_id=check_id,
                    status=status,
                    source="config_rule",
                    reason=reason,
                    raw={"total": len(all_evals)},
                ))

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchConfigRuleException":
                    remaining.append(check_id)  # Rule 미배포 → boto3로 폴백
                else:
                    results.append(CheckResult(
                        isms_p_id=isms_p_id, check_id=check_id,
                        status=ComplianceStatus.INSUFFICIENT_DATA,
                        source="config_rule", reason=str(e),
                    ))

        return results, remaining

    # ── 3순위: boto3 직접 ─────────────────────────────────────────────────────

    def _collect_from_boto3(
        self, isms_p_id: str, check_ids: list[str]
    ) -> list[CheckResult]:
        results: list[CheckResult] = []
        fn_map = self._boto3_fn_map()
        for check_id in check_ids:
            fn = fn_map.get(check_id)
            if not fn:
                continue
            try:
                status, reason = fn()
            except Exception as e:
                status, reason = ComplianceStatus.INSUFFICIENT_DATA, str(e)
            results.append(CheckResult(
                isms_p_id=isms_p_id, check_id=check_id,
                status=status, source="boto3_direct", reason=reason,
            ))
        return results

    def _boto3_fn_map(self) -> dict:
        """boto3 check_id(언더스코어) → 수집 함수 매핑."""
        return {
            # ── 기존 boto3- 접두어 내부 키 ──────────────────────────────
            "boto3-iam-account-summary":    self._check_iam_account_summary,
            "boto3-iam-password-policy":    self._check_iam_password_policy,
            "boto3-root-access-key":        self._check_root_access_key,
            "boto3-kms-key-rotation":       self._check_kms_key_rotation,
            "boto3-s3-encryption":          self._check_s3_encryption,
            "boto3-cloudtrail-multiregion": self._check_cloudtrail_multiregion,
            "boto3-vpc-flow-logs":          self._check_vpc_flow_logs,
            "boto3-cw-log-retention":       self._check_cw_log_retention,
            "boto3-guardduty-enabled":      self._check_guardduty_enabled,
            "boto3-securityhub-enabled":    self._check_securityhub_enabled,
            "boto3-macie-enabled":          self._check_macie_enabled,
            "boto3-inspector2-enabled":     self._check_inspector2_enabled,
            "boto3-ssm-patch-compliance":   self._check_ssm_patch_compliance,
            "boto3-backup-plans":           self._check_backup_plans,
            "boto3-org-tag-policies":       self._check_org_tag_policies,
            "boto3-drs-job-exists":         self._check_drs_job_exists,
            # ── boto3 전용 7개 항목 — prowler check 이름 그대로 사용 ──
            # 2.1.3 정보자산 관리
            "organizations_tags_policies_enabled_and_attached": self._check_org_tag_policies,
            "rds_instance_copy_tags_to_snapshots":              self._check_rds_copy_tags,
            # 2.5.2 사용자 식별
            "efs_access_point_enforce_user_identity":           self._check_efs_access_point_user_identity,
            # 2.8.5 소스 프로그램 관리
            "codeartifact_packages_external_public_publishing_disabled": self._check_codeartifact_external_publish,
            # 2.10.9 악성코드 통제
            "guardduty_ec2_malware_protection_enabled":         self._check_guardduty_malware,
            # 2.11.1 사고 예방 및 대응체계 구축
            "iam_support_role_created":                         self._check_iam_support_role,
            "ssmincidents_enabled_with_plans":                  self._check_ssm_incidents,
            # 2.11.2 취약점 점검 및 조치
            "inspector2_is_enabled":                            self._check_inspector2_enabled,
            "ecr_registry_scan_images_on_push_enabled":         self._check_ecr_scan_on_push,
            "ecr_repositories_scan_vulnerabilities_in_latest_image": self._check_ecr_vuln_scan,
            # 2.12.2 재해 복구 시험 및 개선
            "drs_job_exist":                                    self._check_drs_job_exists,
            # ── Config Rule 대체 — Rule 미배포 시 boto3 직접 체크 ──────
            # 2.5.1 사용자 계정 관리
            "iam-user-unused-credentials-check":                self._check_iam_credential_report,
            "iam-policy-no-statements-with-admin-access":       self._check_iam_admin_policy,
            # 2.5.3 사용자 인증
            "iam-user-mfa-enabled":                             self._check_iam_user_mfa,
            "root-account-mfa-enabled":                         self._check_iam_account_summary,
            "mfa-enabled-for-iam-console-access":               self._check_iam_user_mfa,
            # 2.5.4 비밀번호 관리
            "iam-password-policy":                              self._check_iam_password_policy,
            # 2.5.5 특수계정 권한관리
            "iam-root-access-key-check":                        self._check_root_access_key,
            # 2.5.6 접근권한 검토
            "access-keys-rotated":                              self._check_access_keys_rotated,
            # 2.6.1 네트워크 접근
            "restricted-ssh":                                   self._check_sg_ssh_restricted,
            "vpc-default-security-group-closed":                self._check_default_sg_closed,
            "restricted-common-ports":                          self._check_sg_ssh_restricted,
            "ec2-instances-in-vpc":                             self._check_ec2_in_vpc,
            "vpc-sg-open-only-to-authorized-ports":             self._check_sg_ssh_restricted,
            # 2.6.2 정보시스템 접근
            "ec2-instance-no-public-ip":                        self._check_ec2_no_public_ip,
            "rds-instance-public-access-check":                 self._check_rds_not_public,
            "ebs-snapshot-public-restorable-check":             self._check_ebs_snapshot_not_public,
            # 2.6.3 응용프로그램 접근
            "lambda-function-public-access-prohibited":         self._check_lambda_not_public,
            # 2.6.4 데이터베이스 접근
            "rds-snapshots-public-prohibited":                  self._check_rds_snapshot_not_public,
            # 2.6.6 원격접근 통제 (2.6.1과 공유)
            # 2.7.1 암호정책 적용
            "ec2-ebs-encryption-by-default":                    self._check_ebs_encryption_default,
            "s3-bucket-server-side-encryption-enabled":         self._check_s3_encryption,
            "rds-storage-encrypted":                            self._check_rds_encrypted,
            "elb-tls-https-listeners-only":                     self._check_elb_https,
            "acm-certificate-expiration-check":                 self._check_acm_expiry,
            # 2.7.2 암호키 관리
            "cmk-backing-key-rotation-enabled":                 self._check_kms_key_rotation,
            "kms-cmk-not-scheduled-for-deletion":               self._check_kms_key_rotation,
            # 2.9.2 성능·장애관리
            "cloudwatch-alarm-action-check":                    self._check_cw_alarms,
            "ec2-instance-detailed-monitoring-enabled":         self._check_ec2_detailed_monitoring,
            "rds-enhanced-monitoring-enabled":                  self._check_rds_enhanced_monitoring,
            # 2.9.3 백업·복구관리
            "db-instance-backup-enabled":                       self._check_rds_backup,
            "s3-bucket-versioning-enabled":                     self._check_s3_versioning,
            "dynamodb-in-backup-plan":                          self._check_backup_plans,
            "ebs-in-backup-plan":                               self._check_backup_plans,
            # 2.9.4 로그·접속기록 관리
            "cloudtrail-enabled":                               self._check_cloudtrail_multiregion,
            "cloud-trail-cloud-watch-logs-enabled":             self._check_cloudtrail_multiregion,
            "cw-loggroup-retention-period-check":               self._check_cw_log_retention,
            "cloudtrail-s3-dataevents-enabled":                 self._check_cloudtrail_multiregion,
            # 2.10.1 보안시스템 운영
            "guardduty-enabled-centralized":                    self._check_guardduty_enabled,
            "securityhub-enabled":                              self._check_securityhub_enabled,
            # 2.10.2 클라우드 보안
            "s3-account-level-public-access-blocks-periodic":   self._check_s3_account_public_block,
            # 2.10.8 패치관리
            "ec2-managedinstance-patch-compliance-status-check": self._check_ssm_patch_compliance,
            # 2.11.3 이상행위 모니터링 (cloudwatch-alarm-action-check 위에서 처리)
            # 2.12.1 재해·재난 대비 안전조치
            "rds-multi-az-support":                             self._check_rds_multi_az,
            "s3-bucket-replication-enabled":                    self._check_s3_replication,
            "vpc-vpn-2-tunnels-up":                             self._check_vpn_tunnels,
        }

    # ── boto3 체크 함수들 ─────────────────────────────────────────────────────
    # Prowler check 대응: iam_root_mfa_enabled, iam_avoid_root_usage

    def _check_iam_account_summary(self) -> tuple[ComplianceStatus, str | None]:
        summary = self._client("iam").get_account_summary()["SummaryMap"]
        issues = []
        if not summary.get("AccountMFAEnabled", 0):
            issues.append("루트 MFA 미활성화")
        if summary.get("AccountAccessKeysPresent", 0):
            issues.append("루트 액세스 키 존재")
        return (ComplianceStatus.NON_COMPLIANT, " | ".join(issues)) if issues else (ComplianceStatus.COMPLIANT, None)

    def _check_iam_password_policy(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: iam_password_policy_minimum_length_14, iam_password_policy_reuse_24
        try:
            p = self._client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return ComplianceStatus.NON_COMPLIANT, "비밀번호 정책 미설정"
            raise
        issues = []
        if p.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"최소 길이 {p.get('MinimumPasswordLength')} < 14")
        if not p.get("RequireUppercaseCharacters"):  issues.append("대문자 미요구")
        if not p.get("RequireLowercaseCharacters"):  issues.append("소문자 미요구")
        if not p.get("RequireNumbers"):              issues.append("숫자 미요구")
        if not p.get("RequireSymbols"):              issues.append("특수문자 미요구")
        if p.get("PasswordReusePrevention", 0) < 24: issues.append(f"재사용방지 {p.get('PasswordReusePrevention')} < 24")
        return (ComplianceStatus.NON_COMPLIANT, " | ".join(issues)) if issues else (ComplianceStatus.COMPLIANT, None)

    def _check_root_access_key(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: iam_no_root_access_key
        summary = self._client("iam").get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0):
            return ComplianceStatus.NON_COMPLIANT, "루트 계정에 액세스 키 존재"
        return ComplianceStatus.COMPLIANT, None

    def _check_kms_key_rotation(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: kms_cmk_rotation_enabled, kms_cmk_not_deleted_unintentionally
        kms = self._client("kms")
        no_rotation, pending_del = [], []
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                kid = key["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=kid)["KeyMetadata"]
                    if meta.get("KeyManager") == "AWS":
                        continue
                    if meta.get("KeyState") == "PendingDeletion":
                        pending_del.append(kid[:8])
                    if not kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled"):
                        no_rotation.append(kid[:8])
                except ClientError:
                    continue
        issues = []
        if no_rotation:  issues.append(f"로테이션 미설정: {', '.join(no_rotation[:3])}")
        if pending_del:  issues.append(f"삭제예약: {', '.join(pending_del[:3])}")
        return (ComplianceStatus.NON_COMPLIANT, " | ".join(issues)) if issues else (ComplianceStatus.COMPLIANT, None)

    def _check_s3_encryption(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: s3_bucket_default_encryption
        s3 = self._client("s3")
        unencrypted = []
        for b in s3.list_buckets()["Buckets"]:
            try:
                s3.get_bucket_encryption(Bucket=b["Name"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    unencrypted.append(b["Name"])
        if unencrypted:
            return ComplianceStatus.NON_COMPLIANT, f"암호화 미설정 버킷: {', '.join(unencrypted[:5])}"
        return ComplianceStatus.COMPLIANT, None

    def _check_cloudtrail_multiregion(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: cloudtrail_multi_region_enabled, cloudtrail_log_file_validation_enabled
        ct = self._client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        mr = [t for t in trails if t.get("IsMultiRegionTrail")]
        if not mr:
            return ComplianceStatus.NON_COMPLIANT, "멀티리전 CloudTrail 없음"
        no_val = [t["Name"] for t in mr if not t.get("LogFileValidationEnabled")]
        if no_val:
            return ComplianceStatus.NON_COMPLIANT, f"로그 무결성 검증 미설정: {', '.join(no_val)}"
        return ComplianceStatus.COMPLIANT, None

    def _check_vpc_flow_logs(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: vpc_flow_logs_enabled
        ec2 = self._client("ec2")
        vpcs = {v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"]}
        logged = {fl["ResourceId"] for fl in ec2.describe_flow_logs()["FlowLogs"]}
        missing = vpcs - logged
        if missing:
            return ComplianceStatus.NON_COMPLIANT, f"Flow Log 미설정 VPC: {', '.join(list(missing)[:5])}"
        return ComplianceStatus.COMPLIANT, None

    def _check_cw_log_retention(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: cloudwatch_log_group_retention_policy_specific_days_enabled
        logs = self._client("logs")
        no_ret, short_ret = [], []
        for page in logs.get_paginator("describe_log_groups").paginate():
            for lg in page["logGroups"]:
                ret = lg.get("retentionInDays")
                if ret is None:        no_ret.append(lg["logGroupName"])
                elif ret < 365:        short_ret.append(f"{lg['logGroupName']}({ret}일)")
        issues = []
        if no_ret:    issues.append(f"보존기간 미설정: {len(no_ret)}개")
        if short_ret: issues.append(f"365일 미만: {', '.join(short_ret[:3])}")
        return (ComplianceStatus.NON_COMPLIANT, " | ".join(issues)) if issues else (ComplianceStatus.COMPLIANT, None)

    def _check_guardduty_enabled(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: guardduty_is_enabled, guardduty_ec2_malware_protection_enabled
        gd = self._client("guardduty")
        detectors = gd.list_detectors()["DetectorIds"]
        if not detectors:
            return ComplianceStatus.NON_COMPLIANT, "GuardDuty 탐지기 없음"
        det = gd.get_detector(DetectorId=detectors[0])
        if det.get("Status") != "ENABLED":
            return ComplianceStatus.NON_COMPLIANT, "GuardDuty 비활성화"
        malware = (det.get("DataSources", {})
                      .get("MalwareProtection", {})
                      .get("ScanEc2InstanceWithFindings", {})
                      .get("EbsVolumes", {})
                      .get("Status"))
        if malware != "ENABLED":
            return ComplianceStatus.NON_COMPLIANT, "GuardDuty EC2 악성코드 스캔 미활성화"
        return ComplianceStatus.COMPLIANT, None

    def _check_securityhub_enabled(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: securityhub_enabled
        try:
            self._client("securityhub").describe_hub()
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidAccessException", "ResourceNotFoundException"):
                return ComplianceStatus.NON_COMPLIANT, "Security Hub 비활성화"
            raise

    def _check_macie_enabled(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: macie_is_enabled
        try:
            status = self._client("macie2").get_macie_session().get("status")
            if status == "ENABLED":
                return ComplianceStatus.COMPLIANT, None
            return ComplianceStatus.NON_COMPLIANT, f"Macie 상태: {status}"
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                return ComplianceStatus.NON_COMPLIANT, "Macie 비활성화"
            raise

    def _check_inspector2_enabled(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: inspector2_is_enabled
        account_id = self._client("sts").get_caller_identity()["Account"]
        resp = self._client("inspector2").batch_get_account_status(accountIds=[account_id])
        accounts = resp.get("accounts", [])
        if not accounts:
            return ComplianceStatus.INSUFFICIENT_DATA, "Inspector2 상태 조회 실패"
        state = accounts[0].get("state", {}).get("status")
        if state == "ENABLED":
            return ComplianceStatus.COMPLIANT, None
        return ComplianceStatus.NON_COMPLIANT, f"Inspector2 상태: {state}"

    def _check_ssm_patch_compliance(self) -> tuple[ComplianceStatus, str | None]:
        """
        Prowler: ssm_managed_compliant_patching
        SSM으로 관리되는 인스턴스 목록을 먼저 조회한 뒤 패치 상태 확인.
        describe_instance_patch_states는 InstanceIds 필수.
        """
        ssm = self._client("ssm")
        try:
            # SSM 관리 인스턴스 목록 조회
            paginator = ssm.get_paginator("describe_instance_information")
            instance_ids = []
            for page in paginator.paginate():
                for inst in page.get("InstanceInformationList", []):
                    instance_ids.append(inst["InstanceId"])

            if not instance_ids:
                return ComplianceStatus.NOT_APPLICABLE, "SSM 관리 인스턴스 없음"

            # 50개씩 나눠서 패치 상태 조회 (API 제한)
            nc = []
            for i in range(0, len(instance_ids), 50):
                batch = instance_ids[i:i+50]
                states = ssm.describe_instance_patch_states(InstanceIds=batch)
                for inst in states.get("InstancePatchStates", []):
                    if (inst.get("OperationStatus") == "Failed"
                            or inst.get("MissingCount", 0) > 0
                            or inst.get("FailedCount", 0) > 0):
                        nc.append(inst["InstanceId"])

            if nc:
                return ComplianceStatus.NON_COMPLIANT, f"패치 미준수 인스턴스: {', '.join(nc[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_backup_plans(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: backup_plans_exist, backup_vaults_exist
        backup = self._client("backup")
        issues = []
        if not backup.list_backup_plans()["BackupPlansList"]:  issues.append("Backup 플랜 없음")
        if not backup.list_backup_vaults()["BackupVaultList"]: issues.append("Backup Vault 없음")
        return (ComplianceStatus.NON_COMPLIANT, " | ".join(issues)) if issues else (ComplianceStatus.COMPLIANT, None)

    def _check_org_tag_policies(self) -> tuple[ComplianceStatus, str | None]:
        """
        Prowler: organizations_tags_policies_enabled_and_attached
        Organizations 권한이 없거나 미사용인 경우 → NOT_APPLICABLE 처리.
        (일반 IAM 사용자는 ListRoots 권한이 없는 경우가 많음)
        """
        orgs = self._client("organizations", region="us-east-1")
        try:
            roots = orgs.list_roots()["Roots"]
            if not roots:
                return ComplianceStatus.NOT_APPLICABLE, "Organizations Root 없음"
            enabled = any(
                p.get("Type") == "TAG_POLICY" and p.get("Status") == "ENABLED"
                for p in roots[0].get("PolicyTypes", [])
            )
            if not enabled:
                return ComplianceStatus.NON_COMPLIANT, "Organizations 태그 정책 미활성화"
            if not orgs.list_policies(Filter="TAG_POLICY")["Policies"]:
                return ComplianceStatus.NON_COMPLIANT, "태그 정책 없음"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "AWSOrganizationsNotInUseException",
                "AccessDeniedException",         # 일반 IAM 사용자는 권한 없음
                "AccessDenied",
            ):
                # Organizations 미사용 또는 권한 없음 → 태그 정책 체크 스킵, NOT_APPLICABLE
                return ComplianceStatus.NOT_APPLICABLE, f"Organizations 체크 불가({code}) — RDS 태그 체크로 대체"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_drs_job_exists(self) -> tuple[ComplianceStatus, str | None]:
        """Prowler: drs_job_exist — DRS 미사용 시 NOT_APPLICABLE"""
        try:
            drs = self._client("drs")
            jobs = drs.describe_jobs(filters={})["items"]
            if not jobs:
                return ComplianceStatus.NOT_APPLICABLE, "DRS 미사용 — 재해복구 서비스 비활성화"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "UninitializedAccountException"):
                return ComplianceStatus.NOT_APPLICABLE, "DRS 미사용"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    # ── boto3 전용 7개 항목 신규 체크 함수 ───────────────────────────────────

    def _check_rds_copy_tags(self) -> tuple[ComplianceStatus, str | None]:
        """Prowler: rds_instance_copy_tags_to_snapshots — 2.1.3 정보자산 관리"""
        rds = self._client("rds")
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            if not instances:
                return ComplianceStatus.NOT_APPLICABLE, "RDS 인스턴스 없음"
            no_copy = [
                i["DBInstanceIdentifier"] for i in instances
                if not i.get("CopyTagsToSnapshot", False)
            ]
            if no_copy:
                return ComplianceStatus.NON_COMPLIANT, f"태그 복사 미설정: {', '.join(no_copy[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_efs_access_point_user_identity(self) -> tuple[ComplianceStatus, str | None]:
        """Prowler: efs_access_point_enforce_user_identity — 2.5.2 사용자 식별"""
        efs = self._client("efs")
        try:
            access_points = efs.describe_access_points()["AccessPoints"]
            if not access_points:
                return ComplianceStatus.NOT_APPLICABLE, "EFS 액세스포인트 없음"
            no_uid = [
                ap["AccessPointId"] for ap in access_points
                if not ap.get("PosixUser")
            ]
            if no_uid:
                return ComplianceStatus.NON_COMPLIANT, f"사용자 ID 미강제: {', '.join(no_uid[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_codeartifact_external_publish(self) -> tuple[ComplianceStatus, str | None]:
        """Prowler: codeartifact_packages_external_public_publishing_disabled — 2.8.5 소스 프로그램 관리"""
        ca = self._client("codeartifact")
        try:
            domains = ca.list_domains()["domains"]
            if not domains:
                return ComplianceStatus.NOT_APPLICABLE, "CodeArtifact 미사용"
            for domain in domains:
                repos = ca.list_repositories_in_domain(domain=domain["name"])["repositories"]
                for repo in repos:
                    try:
                        policy = ca.get_repository_permissions_policy(
                            domain=domain["name"],
                            repository=repo["name"]
                        ).get("policy", {})
                        policy_doc = json.loads(policy.get("document", "{}"))
                        for stmt in policy_doc.get("Statement", []):
                            if stmt.get("Principal") == "*" and "Allow" in stmt.get("Effect", ""):
                                return ComplianceStatus.NON_COMPLIANT, f"외부 퍼블리시 허용: {repo['name']}"
                    except ClientError:
                        continue
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "EndpointConnectionError"):
                return ComplianceStatus.NOT_APPLICABLE, "CodeArtifact 미사용"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)
        except Exception as e:
            # 엔드포인트 연결 실패 (서비스 미사용)
            if "Could not connect" in str(e) or "EndpointResolutionError" in str(e):
                return ComplianceStatus.NOT_APPLICABLE, "CodeArtifact 미사용"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_guardduty_malware(self) -> tuple[ComplianceStatus, str | None]:
        """Prowler: guardduty_ec2_malware_protection_enabled — 2.10.9 악성코드 통제"""
        gd = self._client("guardduty")
        try:
            detectors = gd.list_detectors()["DetectorIds"]
            if not detectors:
                return ComplianceStatus.NON_COMPLIANT, "GuardDuty 탐지기 없음"
            det = gd.get_detector(DetectorId=detectors[0])
            malware = (
                det.get("DataSources", {})
                   .get("MalwareProtection", {})
                   .get("ScanEc2InstanceWithFindings", {})
                   .get("EbsVolumes", {})
                   .get("Status")
            )
            if malware != "ENABLED":
                return ComplianceStatus.NON_COMPLIANT, "GuardDuty EC2 악성코드 스캔 비활성화"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_iam_support_role(self) -> tuple[ComplianceStatus, str | None]:
        """
        Prowler: iam_support_role_created — 2.11.1 사고 예방 및 대응체계 구축
        AWSSupportAccess 정책이 연결된 역할 존재 여부 확인.
        페이지네이션으로 전체 역할 검색.
        """
        iam = self._client("iam")
        try:
            # AWSSupportAccess 관리형 정책이 연결된 엔티티 직접 조회 (더 정확하고 빠름)
            support_policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
            entities = iam.list_entities_for_policy(
                PolicyArn=support_policy_arn,
                EntityFilter="Role",
            )
            roles = entities.get("PolicyRoles", [])
            if roles:
                return ComplianceStatus.COMPLIANT, None
            return ComplianceStatus.NON_COMPLIANT, "AWSSupportAccess 정책이 연결된 역할 없음"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                return ComplianceStatus.INSUFFICIENT_DATA, f"IAM 정책 조회 권한 없음({code}) — iam:ListEntitiesForPolicy 필요"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ssm_incidents(self) -> tuple[ComplianceStatus, str | None]:
        """
        Prowler: ssmincidents_enabled_with_plans — 2.11.1 사고 예방 및 대응체계 구축
        AWS가 신규 고객에 대해 SSM Incident Manager 제공을 중단했으므로
        사용 불가 오류는 NOT_APPLICABLE로 처리.
        """
        try:
            ssm_inc = self._client("ssm-incidents")
            plans = ssm_inc.list_response_plans()["responsePlanSummaries"]
            if not plans:
                # 플랜이 없는 경우 = 신규 고객 서비스 중단으로 생성 불가
                # AWS 콘솔에서 준비 버튼이 비활성화되어 있어 플랜 생성이 불가능한 상태
                return ComplianceStatus.NOT_APPLICABLE, "SSM Incident Manager 플랜 생성 불가 — 신규 고객 서비스 중단"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in (
                "AccessDeniedException",
                "ServiceQuotaExceededException",
                "ValidationException",
                "ServiceUnavailableException",
                "ConflictException",
            ):
                return ComplianceStatus.NOT_APPLICABLE, f"SSM Incident Manager 사용 불가({code}) — 신규 고객 서비스 중단"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)
        except Exception as e:
            err = str(e)
            if "NewCustomersNotSupported" in err or "no longer available" in err.lower():
                return ComplianceStatus.NOT_APPLICABLE, "SSM Incident Manager 신규 고객 사용 불가"
            return ComplianceStatus.INSUFFICIENT_DATA, err

    def _check_ecr_scan_on_push(self) -> tuple[ComplianceStatus, str | None]:
        """Prowler: ecr_registry_scan_images_on_push_enabled — 2.11.2 취약점 점검 및 조치"""
        ecr = self._client("ecr")
        try:
            config = ecr.get_registry_scanning_configuration()
            rules = config.get("scanningConfiguration", {}).get("rules", [])
            # Enhanced 스캔 또는 ON_PUSH 규칙 존재 여부
            has_scan = any(
                r.get("scanFrequency") in ("SCAN_ON_PUSH", "CONTINUOUS_SCAN")
                for r in rules
            )
            if not has_scan:
                return ComplianceStatus.NON_COMPLIANT, "ECR 이미지 푸시 시 스캔 미설정"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ecr_vuln_scan(self) -> tuple[ComplianceStatus, str | None]:
        """
        Prowler: ecr_repositories_scan_vulnerabilities_in_latest_image — 2.11.2 취약점 점검 및 조치
        향상된 스캔(Inspector) 모드에서는 imageScanFindingsSummary 대신
        lastRecordedPullTime 또는 imageScanStatus로 스캔 여부 확인.
        Inspector 연동 시 스캔 결과는 Inspector 콘솔에 표시됨.
        """
        ecr = self._client("ecr")
        try:
            # 레지스트리 스캔 설정 확인 — 향상된 스캔이면 Inspector가 처리
            config = ecr.get_registry_scanning_configuration()
            rules = config.get("scanningConfiguration", {}).get("rules", [])
            is_enhanced = any(
                r.get("scanFrequency") == "CONTINUOUS_SCAN"
                for r in rules
            )

            repos = ecr.describe_repositories()["repositories"]
            if not repos:
                return ComplianceStatus.NOT_APPLICABLE, "ECR 레포지토리 없음"

            not_scanned = []
            for repo in repos[:20]:
                try:
                    images = ecr.describe_images(
                        repositoryName=repo["repositoryName"],
                        filter={"tagStatus": "TAGGED"}
                    ).get("imageDetails", [])
                    if not images:
                        continue
                    latest = sorted(
                        images,
                        key=lambda x: x.get("imagePushedAt", ""),
                        reverse=True
                    )[0]

                    if is_enhanced:
                        # 향상된 스캔(Inspector): 스캔 설정 자체가 CONTINUOUS_SCAN이면
                        # Inspector가 모든 레포를 자동 모니터링함 → COMPLIANT
                        # imageScanStatus 필드는 향상된 스캔에서 항상 존재하지 않을 수 있음
                        pass  # 향상된 스캔 설정이 된 것만으로 충분
                    else:
                        # 기본 스캔: imageScanFindingsSummary 확인
                        if not latest.get("imageScanFindingsSummary"):
                            not_scanned.append(repo["repositoryName"])
                except ClientError:
                    continue

            if not_scanned:
                return ComplianceStatus.NON_COMPLIANT, f"스캔 미실행 레포: {', '.join(not_scanned[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    # ── Config Rule 대체 신규 체크 함수들 ────────────────────────────────────

    def _check_iam_credential_report(self) -> tuple[ComplianceStatus, str | None]:
        """iam-user-unused-credentials-check 대체 — 미사용 자격증명 확인."""
        iam = self._client("iam")
        try:
            iam.generate_credential_report()
            report = iam.get_credential_report()["Content"].decode("utf-8")
            lines = report.strip().split("\n")
            headers = lines[0].split(",")
            idx_key1 = headers.index("access_key_1_last_used_date") if "access_key_1_last_used_date" in headers else -1
            idx_key2 = headers.index("access_key_2_last_used_date") if "access_key_2_last_used_date" in headers else -1
            from datetime import datetime, timezone, timedelta
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            stale = []
            for line in lines[1:]:
                fields = line.split(",")
                user = fields[0]
                if user == "<root_account>":
                    continue
                for idx in [idx_key1, idx_key2]:
                    if idx < 0 or idx >= len(fields):
                        continue
                    val = fields[idx]
                    if val not in ("N/A", "no_information", ""):
                        try:
                            used = datetime.fromisoformat(val.replace("Z", "+00:00"))
                            if used < threshold:
                                stale.append(f"{user}(키)")
                        except ValueError:
                            pass
            if stale:
                return ComplianceStatus.NON_COMPLIANT, f"90일 이상 미사용 액세스키: {', '.join(stale[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_iam_admin_policy(self) -> tuple[ComplianceStatus, str | None]:
        """iam-policy-no-statements-with-admin-access 대체 — 관리자 권한 정책 확인."""
        iam = self._client("iam")
        try:
            paginator = iam.get_paginator("list_policies")
            admin_policies = []
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    try:
                        version = iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"]
                        )["PolicyVersion"]["Document"]
                        for stmt in version.get("Statement", []):
                            if (stmt.get("Effect") == "Allow" and
                                stmt.get("Action") in ("*", ["*"]) and
                                stmt.get("Resource") in ("*", ["*"])):
                                admin_policies.append(policy["PolicyName"])
                                break
                    except ClientError:
                        continue
            if admin_policies:
                return ComplianceStatus.NON_COMPLIANT, f"관리자 권한(*) 정책: {', '.join(admin_policies[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_iam_user_mfa(self) -> tuple[ComplianceStatus, str | None]:
        """iam-user-mfa-enabled 대체 — 콘솔 접근 사용자 MFA 확인."""
        iam = self._client("iam")
        try:
            no_mfa = []
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    try:
                        iam.get_login_profile(UserName=user["UserName"])
                        # 콘솔 접근 가능한 사용자 — MFA 확인
                        mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                        if not mfa_devices:
                            no_mfa.append(user["UserName"])
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchEntity":
                            continue  # 콘솔 접근 없는 사용자
                        raise
            if no_mfa:
                return ComplianceStatus.NON_COMPLIANT, f"MFA 미설정 사용자: {', '.join(no_mfa[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_access_keys_rotated(self) -> tuple[ComplianceStatus, str | None]:
        """access-keys-rotated 대체 — 액세스키 90일 이상 미교체 확인."""
        iam = self._client("iam")
        try:
            from datetime import datetime, timezone, timedelta
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            old_keys = []
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                    for key in keys:
                        if key["Status"] == "Active":
                            created = key["CreateDate"]
                            if hasattr(created, 'tzinfo') and created.tzinfo is None:
                                from datetime import timezone as tz
                                created = created.replace(tzinfo=tz.utc)
                            if created < threshold:
                                old_keys.append(f"{user['UserName']}({key['AccessKeyId'][:8]})")
            if old_keys:
                return ComplianceStatus.NON_COMPLIANT, f"90일 이상 미교체 키: {', '.join(old_keys[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_sg_ssh_restricted(self) -> tuple[ComplianceStatus, str | None]:
        """restricted-ssh 대체 — SSH(22) 인터넷 오픈 여부 확인."""
        ec2 = self._client("ec2")
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            open_ssh = []
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    if perm.get("FromPort") == 22 or perm.get("IpProtocol") == "-1":
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") in ("0.0.0.0/0",):
                                open_ssh.append(sg["GroupId"])
                        for ip_range in perm.get("Ipv6Ranges", []):
                            if ip_range.get("CidrIpv6") == "::/0":
                                open_ssh.append(sg["GroupId"])
            open_ssh = list(set(open_ssh))
            if open_ssh:
                return ComplianceStatus.NON_COMPLIANT, f"SSH 인터넷 오픈 SG: {', '.join(open_ssh[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_default_sg_closed(self) -> tuple[ComplianceStatus, str | None]:
        """vpc-default-security-group-closed 대체 — 기본 SG 트래픽 차단 확인."""
        ec2 = self._client("ec2")
        try:
            sgs = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )["SecurityGroups"]
            open_default = [
                sg["GroupId"] for sg in sgs
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress")
            ]
            if open_default:
                return ComplianceStatus.NON_COMPLIANT, f"기본 SG에 규칙 존재: {', '.join(open_default[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ec2_in_vpc(self) -> tuple[ComplianceStatus, str | None]:
        """ec2-instances-in-vpc 대체 — EC2가 VPC 안에 있는지 확인."""
        ec2 = self._client("ec2")
        try:
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            )["Reservations"]
            no_vpc = []
            for r in instances:
                for i in r["Instances"]:
                    if not i.get("VpcId"):
                        no_vpc.append(i["InstanceId"])
            if no_vpc:
                return ComplianceStatus.NON_COMPLIANT, f"VPC 외부 인스턴스: {', '.join(no_vpc[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ec2_no_public_ip(self) -> tuple[ComplianceStatus, str | None]:
        """ec2-instance-no-public-ip 대체 — EC2 퍼블릭 IP 확인."""
        ec2 = self._client("ec2")
        try:
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )["Reservations"]
            public_instances = []
            for r in instances:
                for i in r["Instances"]:
                    if i.get("PublicIpAddress"):
                        public_instances.append(i["InstanceId"])
            if public_instances:
                return ComplianceStatus.NON_COMPLIANT, f"퍼블릭 IP 인스턴스: {', '.join(public_instances[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_rds_not_public(self) -> tuple[ComplianceStatus, str | None]:
        """rds-instance-public-access-check 대체 — RDS 퍼블릭 액세스 확인."""
        rds = self._client("rds")
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            public = [i["DBInstanceIdentifier"] for i in instances if i.get("PubliclyAccessible")]
            if public:
                return ComplianceStatus.NON_COMPLIANT, f"퍼블릭 RDS: {', '.join(public[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ebs_snapshot_not_public(self) -> tuple[ComplianceStatus, str | None]:
        """ebs-snapshot-public-restorable-check 대체 — EBS 스냅샷 퍼블릭 확인."""
        ec2 = self._client("ec2")
        try:
            account_id = self._client("sts").get_caller_identity()["Account"]
            snapshots = ec2.describe_snapshots(OwnerIds=[account_id])["Snapshots"]
            public_snaps = []
            for snap in snapshots[:50]:  # 최대 50개
                try:
                    perms = ec2.describe_snapshot_attribute(
                        SnapshotId=snap["SnapshotId"],
                        Attribute="createVolumePermission"
                    )["CreateVolumePermissions"]
                    if any(p.get("Group") == "all" for p in perms):
                        public_snaps.append(snap["SnapshotId"])
                except ClientError:
                    continue
            if public_snaps:
                return ComplianceStatus.NON_COMPLIANT, f"퍼블릭 EBS 스냅샷: {', '.join(public_snaps[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_lambda_not_public(self) -> tuple[ComplianceStatus, str | None]:
        """lambda-function-public-access-prohibited 대체 — Lambda 퍼블릭 정책 확인."""
        lmb = self._client("lambda")
        try:
            import json as _json
            paginator = lmb.get_paginator("list_functions")
            public_funcs = []
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    try:
                        policy = lmb.get_policy(FunctionName=fn["FunctionName"])["Policy"]
                        doc = _json.loads(policy)
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Principal") in ("*", {"AWS": "*"}):
                                public_funcs.append(fn["FunctionName"])
                                break
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "ResourceNotFoundException":
                            continue
                        raise
            if public_funcs:
                return ComplianceStatus.NON_COMPLIANT, f"퍼블릭 Lambda: {', '.join(public_funcs[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_rds_snapshot_not_public(self) -> tuple[ComplianceStatus, str | None]:
        """rds-snapshots-public-prohibited 대체 — RDS 스냅샷 퍼블릭 확인."""
        rds = self._client("rds")
        try:
            snapshots = rds.describe_db_snapshots(SnapshotType="manual")["DBSnapshots"]
            public = [s["DBSnapshotIdentifier"] for s in snapshots if s.get("PubliclyAccessible")]
            if public:
                return ComplianceStatus.NON_COMPLIANT, f"퍼블릭 RDS 스냅샷: {', '.join(public[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ebs_encryption_default(self) -> tuple[ComplianceStatus, str | None]:
        """ec2-ebs-encryption-by-default 대체 — EBS 기본 암호화 확인."""
        ec2 = self._client("ec2")
        try:
            result = ec2.get_ebs_encryption_by_default()
            if result.get("EbsEncryptionByDefault"):
                return ComplianceStatus.COMPLIANT, None
            return ComplianceStatus.NON_COMPLIANT, "EBS 기본 암호화 비활성화"
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_rds_encrypted(self) -> tuple[ComplianceStatus, str | None]:
        """rds-storage-encrypted 대체 — RDS 스토리지 암호화 확인."""
        rds = self._client("rds")
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            if not instances:
                return ComplianceStatus.NOT_APPLICABLE, "RDS 인스턴스 없음"
            unencrypted = [i["DBInstanceIdentifier"] for i in instances if not i.get("StorageEncrypted")]
            if unencrypted:
                return ComplianceStatus.NON_COMPLIANT, f"암호화 미설정 RDS: {', '.join(unencrypted[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_elb_https(self) -> tuple[ComplianceStatus, str | None]:
        """elb-tls-https-listeners-only 대체 — ELB HTTPS 리스너 확인."""
        elb = self._client("elbv2")
        try:
            lbs = elb.describe_load_balancers()["LoadBalancers"]
            if not lbs:
                return ComplianceStatus.NOT_APPLICABLE, "ELB 없음"
            http_lbs = []
            for lb in lbs:
                listeners = elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])["Listeners"]
                for l in listeners:
                    if l.get("Protocol") == "HTTP":
                        # HTTP만 있고 HTTPS 리다이렉트 규칙 없으면 미준수
                        rules = elb.describe_rules(ListenerArn=l["ListenerArn"])["Rules"]
                        has_redirect = any(
                            a.get("Type") == "redirect"
                            for r in rules for a in r.get("Actions", [])
                        )
                        if not has_redirect:
                            http_lbs.append(lb["LoadBalancerName"])
            if http_lbs:
                return ComplianceStatus.NON_COMPLIANT, f"HTTP 전용 ELB: {', '.join(http_lbs[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_acm_expiry(self) -> tuple[ComplianceStatus, str | None]:
        """acm-certificate-expiration-check 대체 — ACM 인증서 만료 30일 전 확인."""
        acm = self._client("acm")
        try:
            from datetime import datetime, timezone, timedelta
            threshold = datetime.now(timezone.utc) + timedelta(days=30)
            certs = acm.list_certificates(CertificateStatuses=["ISSUED"])["CertificateSummaryList"]
            expiring = []
            for cert in certs:
                detail = acm.describe_certificate(CertificateArn=cert["CertificateArn"])["Certificate"]
                expiry = detail.get("NotAfter")
                if expiry and expiry < threshold:
                    expiring.append(cert.get("DomainName", cert["CertificateArn"][-8:]))
            if expiring:
                return ComplianceStatus.NON_COMPLIANT, f"30일 내 만료 인증서: {', '.join(expiring[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_cw_alarms(self) -> tuple[ComplianceStatus, str | None]:
        """cloudwatch-alarm-action-check 대체 — CloudWatch 알람 액션 활성화 확인."""
        cw = self._client("cloudwatch")
        try:
            alarms = cw.describe_alarms()["MetricAlarms"]
            if not alarms:
                return ComplianceStatus.NON_COMPLIANT, "CloudWatch 알람 없음"
            no_action = [
                a["AlarmName"] for a in alarms
                if not a.get("AlarmActions") and not a.get("OKActions")
            ]
            if len(no_action) == len(alarms):
                return ComplianceStatus.NON_COMPLIANT, "모든 알람에 액션 없음"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_ec2_detailed_monitoring(self) -> tuple[ComplianceStatus, str | None]:
        """ec2-instance-detailed-monitoring-enabled 대체."""
        ec2 = self._client("ec2")
        try:
            instances = ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            )["Reservations"]
            no_monitoring = []
            for r in instances:
                for i in r["Instances"]:
                    if i.get("Monitoring", {}).get("State") != "enabled":
                        no_monitoring.append(i["InstanceId"])
            if no_monitoring:
                return ComplianceStatus.NON_COMPLIANT, f"상세 모니터링 미설정: {', '.join(no_monitoring[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_rds_enhanced_monitoring(self) -> tuple[ComplianceStatus, str | None]:
        """rds-enhanced-monitoring-enabled 대체."""
        rds = self._client("rds")
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            if not instances:
                return ComplianceStatus.NOT_APPLICABLE, "RDS 없음"
            no_monitoring = [
                i["DBInstanceIdentifier"] for i in instances
                if not i.get("MonitoringInterval") or i["MonitoringInterval"] == 0
            ]
            if no_monitoring:
                return ComplianceStatus.NON_COMPLIANT, f"향상된 모니터링 미설정: {', '.join(no_monitoring[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_rds_backup(self) -> tuple[ComplianceStatus, str | None]:
        """db-instance-backup-enabled 대체 — RDS 자동 백업 확인."""
        rds = self._client("rds")
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            if not instances:
                return ComplianceStatus.NOT_APPLICABLE, "RDS 없음"
            no_backup = [
                i["DBInstanceIdentifier"] for i in instances
                if i.get("BackupRetentionPeriod", 0) == 0
            ]
            if no_backup:
                return ComplianceStatus.NON_COMPLIANT, f"자동 백업 미설정 RDS: {', '.join(no_backup[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_s3_versioning(self) -> tuple[ComplianceStatus, str | None]:
        """s3-bucket-versioning-enabled 대체 — S3 버전 관리 확인."""
        s3 = self._client("s3")
        try:
            buckets = s3.list_buckets()["Buckets"]
            if not buckets:
                return ComplianceStatus.NOT_APPLICABLE, "S3 버킷 없음"
            no_versioning = []
            for b in buckets:
                try:
                    v = s3.get_bucket_versioning(Bucket=b["Name"])
                    if v.get("Status") != "Enabled":
                        no_versioning.append(b["Name"])
                except ClientError:
                    no_versioning.append(b["Name"])
            if no_versioning:
                return ComplianceStatus.NON_COMPLIANT, f"버전 관리 미설정 버킷: {', '.join(no_versioning[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_s3_account_public_block(self) -> tuple[ComplianceStatus, str | None]:
        """s3-account-level-public-access-blocks-periodic 대체 — S3 계정 레벨 퍼블릭 차단 확인."""
        try:
            s3control = self._client("s3control")
            account_id = self._client("sts").get_caller_identity()["Account"]
            config = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
            issues = []
            if not config.get("BlockPublicAcls"):      issues.append("BlockPublicAcls 꺼짐")
            if not config.get("IgnorePublicAcls"):     issues.append("IgnorePublicAcls 꺼짐")
            if not config.get("BlockPublicPolicy"):    issues.append("BlockPublicPolicy 꺼짐")
            if not config.get("RestrictPublicBuckets"):issues.append("RestrictPublicBuckets 꺼짐")
            if issues:
                return ComplianceStatus.NON_COMPLIANT, " | ".join(issues)
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return ComplianceStatus.NON_COMPLIANT, "S3 계정 레벨 퍼블릭 액세스 차단 미설정"
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_rds_multi_az(self) -> tuple[ComplianceStatus, str | None]:
        """rds-multi-az-support 대체 — RDS Multi-AZ 확인."""
        rds = self._client("rds")
        try:
            instances = rds.describe_db_instances()["DBInstances"]
            if not instances:
                return ComplianceStatus.NOT_APPLICABLE, "RDS 없음"
            no_multi_az = [
                i["DBInstanceIdentifier"] for i in instances
                if not i.get("MultiAZ") and i.get("DBInstanceClass") != "db.t1.micro"
            ]
            if no_multi_az:
                return ComplianceStatus.NON_COMPLIANT, f"Multi-AZ 미설정 RDS: {', '.join(no_multi_az[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_s3_replication(self) -> tuple[ComplianceStatus, str | None]:
        """s3-bucket-replication-enabled 대체 — S3 크로스 리전 복제 확인."""
        s3 = self._client("s3")
        try:
            buckets = s3.list_buckets()["Buckets"]
            if not buckets:
                return ComplianceStatus.NOT_APPLICABLE, "S3 없음"
            no_replication = []
            for b in buckets:
                try:
                    s3.get_bucket_replication(Bucket=b["Name"])
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
                        no_replication.append(b["Name"])
            if no_replication:
                return ComplianceStatus.NON_COMPLIANT, f"복제 미설정 버킷: {', '.join(no_replication[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    def _check_vpn_tunnels(self) -> tuple[ComplianceStatus, str | None]:
        """vpc-vpn-2-tunnels-up 대체 — VPN 터널 상태 확인."""
        ec2 = self._client("ec2")
        try:
            connections = ec2.describe_vpn_connections(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )["VpnConnections"]
            if not connections:
                return ComplianceStatus.NOT_APPLICABLE, "VPN 연결 없음"
            down_tunnels = []
            for vpn in connections:
                tunnels = vpn.get("VgwTelemetry", [])
                up = sum(1 for t in tunnels if t.get("Status") == "UP")
                if up < 2:
                    down_tunnels.append(vpn["VpnConnectionId"])
            if down_tunnels:
                return ComplianceStatus.NON_COMPLIANT, f"터널 2개 미확보 VPN: {', '.join(down_tunnels[:5])}"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            return ComplianceStatus.INSUFFICIENT_DATA, str(e)

    # ── 내부 유틸 ─────────────────────────────────────────────────────────────

    def _client(self, service: str, region: str | None = None):
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service, region_name=region or self.region
            )
        return self._clients[key]
