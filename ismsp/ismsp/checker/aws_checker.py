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
    둘은 완전히 다른 도구이므로 형식이 다름 (모두 정상)
"""

from __future__ import annotations

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
    ) -> list[CheckResult]:
        """
        1순위 Security Hub → 2순위 Config → 3순위 boto3 순으로 수집.
        처리된 check는 다음 순위로 넘기지 않습니다.
        """
        results: list[CheckResult] = []
        remaining = list(aws_config_rules)

        # 1순위: Security Hub
        sh_results, remaining = self._collect_from_security_hub(isms_p_id, remaining)
        results.extend(sh_results)

        # 2순위: AWS Config (SH가 못 커버한 것만)
        config_results, remaining = self._collect_from_config(isms_p_id, remaining)
        results.extend(config_results)

        # 3순위: boto3 직접 (boto3- 접두어 항목)
        boto3_checks = [c for c in remaining if c in _BOTO3_CHECKS]
        boto3_results = self._collect_from_boto3(isms_p_id, boto3_checks)
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
            if sh_status is None:
                remaining.append(check_id)
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
        fn_map = {
            "boto3-iam-account-summary":  self._check_iam_account_summary,
            "boto3-iam-password-policy":  self._check_iam_password_policy,
            "boto3-root-access-key":      self._check_root_access_key,
            "boto3-kms-key-rotation":     self._check_kms_key_rotation,
            "boto3-s3-encryption":        self._check_s3_encryption,
            "boto3-cloudtrail-multiregion": self._check_cloudtrail_multiregion,
            "boto3-vpc-flow-logs":        self._check_vpc_flow_logs,
            "boto3-cw-log-retention":     self._check_cw_log_retention,
            "boto3-guardduty-enabled":    self._check_guardduty_enabled,
            "boto3-securityhub-enabled":  self._check_securityhub_enabled,
            "boto3-macie-enabled":        self._check_macie_enabled,
            "boto3-inspector2-enabled":   self._check_inspector2_enabled,
            "boto3-ssm-patch-compliance": self._check_ssm_patch_compliance,
            "boto3-backup-plans":         self._check_backup_plans,
            "boto3-org-tag-policies":     self._check_org_tag_policies,
            "boto3-drs-job-exists":       self._check_drs_job_exists,
        }
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
        # Prowler: ssm_managed_compliant_patching
        ssm = self._client("ssm")
        nc = []
        for page in ssm.get_paginator("describe_instance_patch_states").paginate():
            for inst in page.get("InstancePatchStates", []):
                if inst.get("OperationStatus") == "Failed" or inst.get("MissingCount", 0) > 0:
                    nc.append(inst["InstanceId"])
        if nc:
            return ComplianceStatus.NON_COMPLIANT, f"패치 미준수 인스턴스: {', '.join(nc[:5])}"
        return ComplianceStatus.COMPLIANT, None

    def _check_backup_plans(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: backup_plans_exist, backup_vaults_exist
        backup = self._client("backup")
        issues = []
        if not backup.list_backup_plans()["BackupPlansList"]:  issues.append("Backup 플랜 없음")
        if not backup.list_backup_vaults()["BackupVaultList"]: issues.append("Backup Vault 없음")
        return (ComplianceStatus.NON_COMPLIANT, " | ".join(issues)) if issues else (ComplianceStatus.COMPLIANT, None)

    def _check_org_tag_policies(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: organizations_tags_policies_enabled_and_attached
        orgs = self._client("organizations", region="us-east-1")
        try:
            roots = orgs.list_roots()["Roots"]
            if not roots:
                return ComplianceStatus.INSUFFICIENT_DATA, "Organizations Root 없음"
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
            if e.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
                return ComplianceStatus.INSUFFICIENT_DATA, "AWS Organizations 미사용"
            raise

    def _check_drs_job_exists(self) -> tuple[ComplianceStatus, str | None]:
        # Prowler: drs_job_exist
        try:
            drs = self._client("drs")
            jobs = drs.describe_jobs(filters={})["items"]
            if not jobs:
                return ComplianceStatus.NON_COMPLIANT, "DRS 복구 작업 없음"
            return ComplianceStatus.COMPLIANT, None
        except ClientError as e:
            if e.response["Error"]["Code"] in ("AccessDeniedException", "UninitializedAccountException"):
                return ComplianceStatus.INSUFFICIENT_DATA, "DRS 미활성화"
            raise

    # ── 내부 유틸 ─────────────────────────────────────────────────────────────

    def _client(self, service: str, region: str | None = None):
        key = f"{service}:{region or self.region}"
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service, region_name=region or self.region
            )
        return self._clients[key]
