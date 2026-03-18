"""
ISMS-P 점검 항목 평가 모듈

수집된 AWS 설정 데이터와 ISMS-P 매핑을 비교하여 각 항목의 충족/미충족 여부를 판정합니다.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 상수
# ---------------------------------------------------------------------------
ACCESS_KEY_MAX_AGE_DAYS = 90
PASSWORD_MIN_LENGTH = 8
RDS_BACKUP_MIN_DAYS = 7
LOG_RETENTION_MIN_DAYS = 365
CRITICAL_PORTS = {22, 3389}


# ---------------------------------------------------------------------------
# 매핑 로드
# ---------------------------------------------------------------------------

def load_mapping() -> list:
    """isms_mapping.json을 로드하여 항목 목록을 반환합니다."""
    mapping_path = Path(__file__).parent.parent / "mappings" / "isms_mapping.json"
    with open(mapping_path, encoding="utf-8") as f:
        data = json.load(f)
    return data["items"]


def normalize_mapping(mapping: Any) -> list[dict]:
    if mapping is None:
        return load_mapping()

    if isinstance(mapping, (str, Path)):
        with open(mapping, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            items = data.get("items", [])
            return items if isinstance(items, list) else []
        return data if isinstance(data, list) else []

    if isinstance(mapping, dict):
        items = mapping.get("items", [])
        return items if isinstance(items, list) else []

    return mapping if isinstance(mapping, list) else []


# ---------------------------------------------------------------------------
# 날짜 파싱 헬퍼
# ---------------------------------------------------------------------------

def _parse_dt(value) -> datetime | None:
    """문자열이나 datetime 객체를 UTC-aware datetime으로 변환합니다."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S+00:00"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    try:
        # ISO 8601 via fromisoformat (Python 3.11+에서 완전 지원)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 개별 check_type 핸들러
# ---------------------------------------------------------------------------

def _check_mfa_enabled(aws_config: dict) -> tuple[str, str, dict]:
    """IAM 사용자 MFA 활성화 여부를 확인합니다."""
    iam = aws_config.get("iam", {})
    users = iam.get("users", [])
    mfa_by_user = iam.get("mfa_by_user", {})

    if not users:
        return "NA", "IAM 사용자가 없습니다.", {}

    users_without_mfa = [
        u["UserName"]
        for u in users
        if not mfa_by_user.get(u["UserName"])
    ]

    if users_without_mfa:
        return (
            "FAIL",
            f"MFA 미설정 사용자 {len(users_without_mfa)}명: {', '.join(users_without_mfa)}",
            {"users_without_mfa": users_without_mfa, "total_users": len(users)},
        )
    return (
        "PASS",
        f"전체 {len(users)}명의 IAM 사용자에 MFA가 설정되어 있습니다.",
        {"total_users": len(users)},
    )


def _check_root_mfa(aws_config: dict) -> tuple[str, str, dict]:
    """루트 계정 MFA 활성화 여부를 확인합니다."""
    summary = aws_config.get("iam", {}).get("account_summary", {})
    mfa_enabled = summary.get("AccountMFAEnabled", 0)

    if mfa_enabled == 1:
        return "PASS", "루트 계정에 MFA가 활성화되어 있습니다.", {"AccountMFAEnabled": True}
    return "FAIL", "루트 계정에 MFA가 활성화되어 있지 않습니다.", {"AccountMFAEnabled": False}


def _check_password_policy(aws_config: dict) -> tuple[str, str, dict]:
    """IAM 패스워드 정책 강도를 확인합니다."""
    policy = aws_config.get("iam", {}).get("password_policy")
    if policy is None:
        return "FAIL", "IAM 패스워드 정책이 설정되어 있지 않습니다.", {}

    failures = []
    if policy.get("MinimumPasswordLength", 0) < PASSWORD_MIN_LENGTH:
        failures.append(f"최소 길이 {policy.get('MinimumPasswordLength', 0)}자 (기준: {PASSWORD_MIN_LENGTH}자 이상)")
    if not policy.get("RequireUppercaseCharacters"):
        failures.append("대문자 포함 미요구")
    if not policy.get("RequireLowercaseCharacters"):
        failures.append("소문자 포함 미요구")
    if not policy.get("RequireNumbers"):
        failures.append("숫자 포함 미요구")
    if not policy.get("RequireSymbols"):
        failures.append("특수문자 포함 미요구")

    if failures:
        return "FAIL", "패스워드 정책 미충족: " + "; ".join(failures), {"policy": policy, "failures": failures}
    return "PASS", "IAM 패스워드 정책이 보안 기준을 충족합니다.", {"policy": policy}


def _check_access_key_age(aws_config: dict) -> tuple[str, str, dict]:
    """90일 이상 된 액세스 키 존재 여부를 확인합니다."""
    access_keys = aws_config.get("iam", {}).get("access_keys", {})
    now = datetime.now(timezone.utc)
    old_keys = []

    for username, keys in access_keys.items():
        for key in keys:
            if key.get("Status") != "Active":
                continue
            created = _parse_dt(key.get("CreateDate"))
            if created and (now - created).days > ACCESS_KEY_MAX_AGE_DAYS:
                old_keys.append({
                    "username": username,
                    "key_id": key.get("AccessKeyId"),
                    "age_days": (now - created).days,
                })

    if old_keys:
        return (
            "FAIL",
            f"{ACCESS_KEY_MAX_AGE_DAYS}일 이상 된 활성 액세스 키 {len(old_keys)}개 발견",
            {"old_keys": old_keys},
        )
    return "PASS", f"모든 활성 액세스 키가 {ACCESS_KEY_MAX_AGE_DAYS}일 이내에 생성되었습니다.", {}


def _check_no_root_access_key(aws_config: dict) -> tuple[str, str, dict]:
    """루트 계정 액세스 키 비활성화 여부를 확인합니다."""
    summary = aws_config.get("iam", {}).get("account_summary", {})
    has_key = summary.get("AccountAccessKeysPresent", 0)

    if has_key == 0:
        return "PASS", "루트 계정 액세스 키가 존재하지 않습니다.", {}
    return "FAIL", "루트 계정에 활성 액세스 키가 존재합니다. 즉시 삭제하세요.", {"AccountAccessKeysPresent": has_key}


def _check_vpc_isolation(aws_config: dict) -> tuple[str, str, dict]:
    """VPC에 퍼블릭/프라이빗 서브넷이 분리되어 있는지 확인합니다."""
    subnets = aws_config.get("ec2", {}).get("subnets", [])
    vpcs = aws_config.get("ec2", {}).get("vpcs", [])

    if not vpcs:
        return "NA", "VPC가 없습니다.", {}

    vpc_subnet_map: dict[str, dict] = {}
    for subnet in subnets:
        vpc_id = subnet.get("VpcId", "")
        if vpc_id not in vpc_subnet_map:
            vpc_subnet_map[vpc_id] = {"public": [], "private": []}
        if subnet.get("MapPublicIpOnLaunch"):
            vpc_subnet_map[vpc_id]["public"].append(subnet["SubnetId"])
        else:
            vpc_subnet_map[vpc_id]["private"].append(subnet["SubnetId"])

    vpcs_without_isolation = [
        vpc_id
        for vpc_id, sn in vpc_subnet_map.items()
        if not (sn["public"] and sn["private"])
    ]

    if vpcs_without_isolation:
        return (
            "FAIL",
            f"퍼블릭/프라이빗 서브넷 분리가 미흡한 VPC: {', '.join(vpcs_without_isolation)}",
            {"vpc_subnet_map": vpc_subnet_map},
        )
    return (
        "PASS",
        f"점검된 {len(vpc_subnet_map)}개 VPC 모두 퍼블릭/프라이빗 서브넷이 분리되어 있습니다.",
        {"vpc_subnet_map": vpc_subnet_map},
    )


def _check_sg_open_ingress(aws_config: dict) -> tuple[str, str, dict]:
    """SG에서 0.0.0.0/0 으로부터 SSH(22)/RDP(3389) 허용 여부를 확인합니다."""
    sgs = aws_config.get("ec2", {}).get("security_groups", [])
    violations = []

    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            proto = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            open_cidrs = [
                r["CidrIp"] for r in rule.get("IpRanges", [])
                if r.get("CidrIp") in ("0.0.0.0/0",)
            ] + [
                r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                if r.get("CidrIpv6") in ("::/0",)
            ]

            if not open_cidrs:
                continue

            if proto == "-1":
                violations.append({"sg_id": sg["GroupId"], "sg_name": sg.get("GroupName"), "reason": "All traffic 허용", "cidrs": open_cidrs})
            elif proto == "tcp":
                for port in CRITICAL_PORTS:
                    if from_port <= port <= to_port:
                        violations.append({"sg_id": sg["GroupId"], "sg_name": sg.get("GroupName"), "port": port, "cidrs": open_cidrs})

    if violations:
        return "FAIL", f"0.0.0.0/0 SSH/RDP 허용 보안 그룹 {len(violations)}건 발견", {"violations": violations}
    return "PASS", "0.0.0.0/0 으로부터 SSH/RDP를 허용하는 보안 그룹이 없습니다.", {}


def _check_nacl_default_deny(aws_config: dict) -> tuple[str, str, dict]:
    """NACL에 명시적 거부 규칙이 있는지 확인합니다."""
    nacls = aws_config.get("ec2", {}).get("network_acls", [])
    if not nacls:
        return "NA", "NACL이 없습니다.", {}

    nacls_without_deny = []
    for nacl in nacls:
        has_deny = any(
            e.get("RuleAction") == "deny"
            for e in nacl.get("Entries", [])
            if not e.get("Egress", True)  # 인바운드 규칙만 확인
        )
        if not has_deny:
            nacls_without_deny.append(nacl["NetworkAclId"])

    if nacls_without_deny:
        return (
            "FAIL",
            f"명시적 거부 규칙이 없는 NACL: {', '.join(nacls_without_deny)}",
            {"nacls_without_deny": nacls_without_deny},
        )
    return "PASS", "모든 NACL에 명시적 거부 규칙이 존재합니다.", {}


def _check_sg_unrestricted_all(aws_config: dict) -> tuple[str, str, dict]:
    """SG에서 0.0.0.0/0 으로부터 모든 트래픽을 허용하는지 확인합니다."""
    sgs = aws_config.get("ec2", {}).get("security_groups", [])
    violations = []

    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            if rule.get("IpProtocol") != "-1":
                continue
            open_cidrs = [r["CidrIp"] for r in rule.get("IpRanges", []) if r.get("CidrIp") in ("0.0.0.0/0",)]
            open_cidrs += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") in ("::/0",)]
            if open_cidrs:
                violations.append({"sg_id": sg["GroupId"], "sg_name": sg.get("GroupName"), "cidrs": open_cidrs})

    if violations:
        return "FAIL", f"모든 트래픽을 전체 허용하는 보안 그룹 {len(violations)}개 발견", {"violations": violations}
    return "PASS", "모든 트래픽을 허용하는 보안 그룹이 없습니다.", {}


def _check_rds_not_public(aws_config: dict) -> tuple[str, str, dict]:
    """RDS 인스턴스가 퍼블릭 접근 허용 여부를 확인합니다."""
    instances = aws_config.get("rds", {}).get("db_instances", [])
    if not instances:
        return "NA", "RDS 인스턴스가 없습니다.", {}

    public_instances = [
        i["DBInstanceIdentifier"]
        for i in instances
        if i.get("PubliclyAccessible", False)
    ]

    if public_instances:
        return "FAIL", f"퍼블릭 접근이 허용된 RDS 인스턴스: {', '.join(public_instances)}", {"public_instances": public_instances}
    return "PASS", f"모든 {len(instances)}개 RDS 인스턴스가 퍼블릭 접근 불가 상태입니다.", {}


def _check_s3_public_block(aws_config: dict) -> tuple[str, str, dict]:
    """S3 퍼블릭 접근 차단 설정 여부를 확인합니다."""
    buckets = aws_config.get("s3", {}).get("buckets", [])
    pab_map = aws_config.get("s3", {}).get("public_access_block", {})

    if not buckets:
        return "NA", "S3 버킷이 없습니다.", {}

    violations = []
    for bucket in buckets:
        name = bucket["Name"]
        pab = pab_map.get(name)
        if not pab:
            violations.append({"bucket": name, "reason": "퍼블릭 접근 차단 설정 없음"})
            continue
        if not all([
            pab.get("BlockPublicAcls"),
            pab.get("IgnorePublicAcls"),
            pab.get("BlockPublicPolicy"),
            pab.get("RestrictPublicBuckets"),
        ]):
            violations.append({"bucket": name, "pab": pab})

    if violations:
        return "FAIL", f"퍼블릭 접근 차단 미설정 버킷 {len(violations)}개 발견", {"violations": violations}
    return "PASS", f"모든 {len(buckets)}개 S3 버킷에 퍼블릭 접근 차단이 설정되어 있습니다.", {}


def _check_s3_acl_public_write(aws_config: dict) -> tuple[str, str, dict]:
    """S3 버킷 ACL 퍼블릭 쓰기 권한 여부를 확인합니다."""
    buckets = aws_config.get("s3", {}).get("buckets", [])
    acl_map = aws_config.get("s3", {}).get("bucket_acl", {})

    if not buckets:
        return "NA", "S3 버킷이 없습니다.", {}

    public_uris = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    write_perms = {"WRITE", "WRITE_ACP", "FULL_CONTROL"}
    violations = []

    for bucket in buckets:
        name = bucket["Name"]
        acl = acl_map.get(name, {})
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            perm = grant.get("Permission", "")
            uri = grantee.get("URI", "")
            if uri in public_uris and perm in write_perms:
                violations.append({"bucket": name, "grantee_uri": uri, "permission": perm})

    if violations:
        return "FAIL", f"퍼블릭 쓰기 권한이 설정된 버킷 {len(violations)}개 발견", {"violations": violations}
    return "PASS", "퍼블릭 쓰기 권한이 부여된 S3 버킷이 없습니다.", {}


def _check_s3_encryption(aws_config: dict) -> tuple[str, str, dict]:
    """S3 버킷 서버 사이드 암호화(SSE) 여부를 확인합니다."""
    buckets = aws_config.get("s3", {}).get("buckets", [])
    enc_map = aws_config.get("s3", {}).get("bucket_encryption", {})

    if not buckets:
        return "NA", "S3 버킷이 없습니다.", {}

    unencrypted = [b["Name"] for b in buckets if not enc_map.get(b["Name"])]

    if unencrypted:
        return "FAIL", f"서버 사이드 암호화 미설정 버킷 {len(unencrypted)}개: {', '.join(unencrypted)}", {"unencrypted_buckets": unencrypted}
    return "PASS", f"모든 {len(buckets)}개 S3 버킷에 서버 사이드 암호화가 설정되어 있습니다.", {}


def _check_rds_encryption(aws_config: dict) -> tuple[str, str, dict]:
    """RDS 인스턴스 저장 암호화 여부를 확인합니다."""
    instances = aws_config.get("rds", {}).get("db_instances", [])
    if not instances:
        return "NA", "RDS 인스턴스가 없습니다.", {}

    unencrypted = [i["DBInstanceIdentifier"] for i in instances if not i.get("StorageEncrypted")]

    if unencrypted:
        return "FAIL", f"암호화 미적용 RDS 인스턴스: {', '.join(unencrypted)}", {"unencrypted_instances": unencrypted}
    return "PASS", f"모든 {len(instances)}개 RDS 인스턴스에 저장 암호화가 적용되어 있습니다.", {}


def _check_ebs_encryption(aws_config: dict) -> tuple[str, str, dict]:
    """EC2 계정 수준 EBS 기본 암호화 활성화 여부를 확인합니다."""
    enabled = aws_config.get("ec2", {}).get("ebs_encryption_by_default", False)
    if enabled:
        return "PASS", "EBS 볼륨 기본 암호화가 활성화되어 있습니다.", {"enabled": True}
    return "FAIL", "EBS 볼륨 기본 암호화가 비활성화 상태입니다.", {"enabled": False}


def _check_elb_https_listener(aws_config: dict) -> tuple[str, str, dict]:
    """ELB HTTPS 리스너 설정 여부를 확인합니다."""
    lbs = aws_config.get("elbv2", {}).get("load_balancers", [])
    listeners_map = aws_config.get("elbv2", {}).get("listeners", {})

    if not lbs:
        return "NA", "로드 밸런서가 없습니다.", {}

    violations = []
    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        listeners = listeners_map.get(arn, [])
        has_https = any(l.get("Protocol") in ("HTTPS", "TLS") for l in listeners)
        if not has_https:
            violations.append(lb.get("DNSName", arn))

    if violations:
        return "FAIL", f"HTTPS/TLS 리스너가 없는 로드 밸런서: {', '.join(violations)}", {"violations": violations}
    return "PASS", f"모든 {len(lbs)}개 로드 밸런서에 HTTPS 리스너가 구성되어 있습니다.", {}


def _check_kms_key_rotation(aws_config: dict) -> tuple[str, str, dict]:
    """KMS 고객 관리형 키 자동 교체 여부를 확인합니다."""
    rotation_status = aws_config.get("kms", {}).get("rotation_status", {})
    key_details = aws_config.get("kms", {}).get("key_details", {})

    customer_keys = [
        key_id for key_id, d in key_details.items()
        if d.get("KeyMetadata", {}).get("KeyManager") == "CUSTOMER"
        and d.get("KeyMetadata", {}).get("KeyState") == "Enabled"
    ]

    if not customer_keys:
        return "NA", "고객 관리형 KMS 키가 없습니다.", {}

    no_rotation = [
        key_id for key_id in customer_keys
        if not rotation_status.get(key_id, {}).get("KeyRotationEnabled", False)
    ]

    if no_rotation:
        return "FAIL", f"자동 교체 미설정 KMS 키 {len(no_rotation)}개: {', '.join(no_rotation)}", {"no_rotation": no_rotation}
    return "PASS", f"모든 {len(customer_keys)}개 고객 관리형 KMS 키에 자동 교체가 활성화되어 있습니다.", {}


def _check_kms_key_active(aws_config: dict) -> tuple[str, str, dict]:
    """KMS 키가 활성화 상태인지 확인합니다."""
    key_details = aws_config.get("kms", {}).get("key_details", {})
    if not key_details:
        return "NA", "KMS 키가 없습니다.", {}

    inactive_keys = [
        key_id for key_id, d in key_details.items()
        if d.get("KeyMetadata", {}).get("KeyManager") == "CUSTOMER"
        and d.get("KeyMetadata", {}).get("KeyState") not in ("Enabled",)
    ]

    if inactive_keys:
        return "FAIL", f"비활성화 또는 삭제 예정 KMS 키 {len(inactive_keys)}개 발견", {"inactive_keys": inactive_keys}
    return "PASS", "모든 고객 관리형 KMS 키가 활성화 상태입니다.", {}


def _check_ssm_managed(aws_config: dict) -> tuple[str, str, dict]:
    """EC2 인스턴스가 SSM으로 관리되는지 확인합니다."""
    instances = aws_config.get("ec2", {}).get("instances", [])
    managed = aws_config.get("ssm", {}).get("managed_instances", [])

    if not instances:
        return "NA", "EC2 인스턴스가 없습니다.", {}

    managed_ids = {m["InstanceId"] for m in managed if m.get("PingStatus") == "Online"}
    running_ids = {i["InstanceId"] for i in instances if i.get("State", {}).get("Name") == "running"}

    unmanaged = running_ids - managed_ids

    if unmanaged:
        return "FAIL", f"SSM 미등록 EC2 인스턴스 {len(unmanaged)}개: {', '.join(unmanaged)}", {"unmanaged": list(unmanaged)}
    return "PASS", f"모든 {len(running_ids)}개 실행 중인 EC2 인스턴스가 SSM에 등록되어 있습니다.", {}


def _check_ssm_patch_compliance(aws_config: dict) -> tuple[str, str, dict]:
    """SSM 패치 준수 상태를 확인합니다."""
    patch_states = aws_config.get("ssm", {}).get("patch_states", [])
    if not patch_states:
        return "NA", "SSM 패치 상태 정보가 없습니다.", {}

    non_compliant = [
        {"instance_id": p["InstanceId"], "missing": p.get("MissingCount", 0)}
        for p in patch_states
        if p.get("MissingCount", 0) > 0 or p.get("FailedCount", 0) > 0
    ]

    if non_compliant:
        return "FAIL", f"패치 미적용 인스턴스 {len(non_compliant)}개 발견", {"non_compliant": non_compliant}
    return "PASS", f"모든 {len(patch_states)}개 인스턴스가 패치 기준을 충족합니다.", {}


def _check_cloudtrail_enabled(aws_config: dict) -> tuple[str, str, dict]:
    """CloudTrail 활성화 및 전 리전 적용 여부를 확인합니다."""
    trails = aws_config.get("cloudtrail", {}).get("trails", [])
    trail_status = aws_config.get("cloudtrail", {}).get("trail_status", {})

    if not trails:
        return "FAIL", "CloudTrail 트레일이 설정되어 있지 않습니다.", {}

    active_multiregion = [
        t["Name"]
        for t in trails
        if t.get("IsMultiRegionTrail")
        and trail_status.get(t["Name"], {}).get("IsLogging", False)
    ]

    if not active_multiregion:
        return "FAIL", "활성화된 멀티 리전 CloudTrail 트레일이 없습니다.", {"trails": [t["Name"] for t in trails]}
    return "PASS", f"멀티 리전 CloudTrail 트레일 {len(active_multiregion)}개가 활성화되어 있습니다.", {"active_trails": active_multiregion}


def _check_cloudtrail_encrypted(aws_config: dict) -> tuple[str, str, dict]:
    """CloudTrail 로그 KMS 암호화 여부를 확인합니다."""
    trails = aws_config.get("cloudtrail", {}).get("trails", [])
    if not trails:
        return "NA", "CloudTrail 트레일이 없습니다.", {}

    unencrypted = [t["Name"] for t in trails if not t.get("KMSKeyId")]

    if unencrypted:
        return "FAIL", f"KMS 암호화 미적용 CloudTrail 트레일: {', '.join(unencrypted)}", {"unencrypted_trails": unencrypted}
    return "PASS", "모든 CloudTrail 트레일에 KMS 암호화가 적용되어 있습니다.", {}


def _check_cloudtrail_log_validation(aws_config: dict) -> tuple[str, str, dict]:
    """CloudTrail 로그 파일 무결성 검증 활성화 여부를 확인합니다."""
    trails = aws_config.get("cloudtrail", {}).get("trails", [])
    if not trails:
        return "NA", "CloudTrail 트레일이 없습니다.", {}

    no_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]

    if no_validation:
        return "FAIL", f"로그 파일 무결성 검증 미설정 트레일: {', '.join(no_validation)}", {"no_validation": no_validation}
    return "PASS", "모든 CloudTrail 트레일에 로그 파일 무결성 검증이 활성화되어 있습니다.", {}


def _check_vpc_flow_logs(aws_config: dict) -> tuple[str, str, dict]:
    """VPC Flow Logs 활성화 여부를 확인합니다."""
    vpcs = aws_config.get("ec2", {}).get("vpcs", [])
    flow_logs = aws_config.get("ec2", {}).get("flow_logs", [])

    if not vpcs:
        return "NA", "VPC가 없습니다.", {}

    active_vpc_logs = {
        fl["ResourceId"]
        for fl in flow_logs
        if fl.get("FlowLogStatus") == "ACTIVE"
    }

    vpcs_without_logs = [v["VpcId"] for v in vpcs if v["VpcId"] not in active_vpc_logs]

    if vpcs_without_logs:
        return "FAIL", f"Flow Logs 미설정 VPC: {', '.join(vpcs_without_logs)}", {"vpcs_without_logs": vpcs_without_logs}
    return "PASS", f"모든 {len(vpcs)}개 VPC에 Flow Logs가 활성화되어 있습니다.", {}


def _check_guardduty_enabled(aws_config: dict) -> tuple[str, str, dict]:
    """GuardDuty 활성화 여부를 확인합니다."""
    detectors = aws_config.get("guardduty", {}).get("detectors", [])
    details = aws_config.get("guardduty", {}).get("detector_details", {})

    enabled_detectors = [
        d for d in detectors
        if details.get(d, {}).get("Status") == "ENABLED"
    ]

    if enabled_detectors:
        return "PASS", f"GuardDuty가 활성화되어 있습니다 (detector: {', '.join(enabled_detectors)}).", {"detectors": enabled_detectors}
    return "FAIL", "GuardDuty가 활성화되어 있지 않습니다.", {}


def _check_guardduty_findings(aws_config: dict) -> tuple[str, str, dict]:
    """GuardDuty 고위험 Finding 존재 여부를 확인합니다."""
    detectors = aws_config.get("guardduty", {}).get("detectors", [])
    if not detectors:
        return "NA", "GuardDuty가 활성화되어 있지 않습니다.", {}

    findings = aws_config.get("guardduty", {}).get("findings", [])
    if findings:
        return "FAIL", f"GuardDuty 고위험 Finding {len(findings)}건이 미처리 상태입니다.", {"findings_count": len(findings)}
    return "PASS", "GuardDuty에 미처리된 고위험 Finding이 없습니다.", {}


def _check_securityhub_enabled(aws_config: dict) -> tuple[str, str, dict]:
    """SecurityHub 활성화 여부를 확인합니다."""
    hub_arn = aws_config.get("securityhub", {}).get("hub_arn")
    if hub_arn:
        standards = aws_config.get("securityhub", {}).get("subscribed_standards", [])
        return "PASS", f"Security Hub가 활성화되어 있습니다 ({len(standards)}개 보안 표준 구독).", {"hub_arn": hub_arn}
    return "FAIL", "AWS Security Hub가 활성화되어 있지 않습니다.", {}


def _check_cloudwatch_alarms(aws_config: dict) -> tuple[str, str, dict]:
    """CloudWatch 알람 설정 여부를 확인합니다."""
    alarms = aws_config.get("cloudwatch", {}).get("alarms", [])
    if not alarms:
        return "FAIL", "CloudWatch 알람이 설정되어 있지 않습니다.", {}

    active_alarms = [a for a in alarms if a.get("ActionsEnabled", False)]
    if len(active_alarms) < 3:
        return "FAIL", f"CloudWatch 알람이 {len(active_alarms)}개로 부족합니다 (최소 3개 권장).", {"alarm_count": len(active_alarms)}
    return "PASS", f"CloudWatch 알람 {len(active_alarms)}개가 활성화되어 있습니다.", {"alarm_count": len(active_alarms)}


def _check_config_enabled(aws_config: dict) -> tuple[str, str, dict]:
    """AWS Config 구성 레코더 활성화 여부를 확인합니다."""
    recorders = aws_config.get("config", {}).get("configuration_recorders", [])
    statuses = aws_config.get("config", {}).get("recorder_statuses", [])

    if not recorders:
        return "FAIL", "AWS Config 구성 레코더가 설정되어 있지 않습니다.", {}

    active_recorders = [s for s in statuses if s.get("recording", False)]
    if not active_recorders:
        return "FAIL", "AWS Config 구성 레코더가 비활성 상태입니다.", {"recorders": recorders}
    return "PASS", f"AWS Config 구성 레코더 {len(active_recorders)}개가 활성화되어 있습니다.", {}


def _check_cloudwatch_log_retention(aws_config: dict) -> tuple[str, str, dict]:
    """CloudWatch Log 그룹 보존 기간 설정 여부를 확인합니다."""
    log_groups = aws_config.get("cloudwatch", {}).get("log_groups", [])
    if not log_groups:
        return "NA", "CloudWatch Log 그룹이 없습니다.", {}

    violations = [
        {"name": lg["logGroupName"], "retention": lg.get("retentionInDays")}
        for lg in log_groups
        if not lg.get("retentionInDays") or lg.get("retentionInDays", 0) < LOG_RETENTION_MIN_DAYS
    ]

    if violations:
        return "FAIL", f"보존 기간 {LOG_RETENTION_MIN_DAYS}일 미만 Log 그룹 {len(violations)}개 발견", {"violations": violations}
    return "PASS", f"모든 {len(log_groups)}개 Log 그룹의 보존 기간이 기준을 충족합니다.", {}


def _check_config_rules_compliant(aws_config: dict) -> tuple[str, str, dict]:
    """AWS Config Rules 준수 여부를 확인합니다."""
    compliance = aws_config.get("config", {}).get("compliance_summary", {})
    if not compliance:
        return "NA", "AWS Config Rules 정보가 없습니다.", {}

    non_compliant = compliance.get("non_compliant_rules", 0)
    compliant = compliance.get("compliant_rules", 0)

    if non_compliant > 0:
        return "FAIL", f"Config Rules 위반 {non_compliant}건이 발견되었습니다.", {"non_compliant": non_compliant, "compliant": compliant}
    return "PASS", f"모든 Config Rules가 준수 상태입니다 (준수: {compliant}개).", {}


def _check_inspector_enabled(aws_config: dict) -> tuple[str, str, dict]:
    """Amazon Inspector v2 활성화 여부를 확인합니다."""
    inspector = aws_config.get("inspector", {})
    if inspector.get("enabled"):
        return "PASS", "Amazon Inspector v2가 활성화되어 있습니다.", {}
    return "FAIL", "Amazon Inspector v2가 활성화되어 있지 않습니다.", {}


def _check_inspector_findings(aws_config: dict) -> tuple[str, str, dict]:
    """Inspector 고위험 취약점 미조치 여부를 확인합니다."""
    inspector = aws_config.get("inspector", {})
    if not inspector.get("enabled"):
        return "NA", "Amazon Inspector가 활성화되어 있지 않습니다.", {}

    findings = inspector.get("findings", [])
    if findings:
        return "FAIL", f"Inspector CRITICAL/HIGH 취약점 {len(findings)}건이 미조치 상태입니다.", {"findings_count": len(findings)}
    return "PASS", "Inspector에서 미조치된 CRITICAL/HIGH 취약점이 없습니다.", {}


def _check_rds_backup(aws_config: dict) -> tuple[str, str, dict]:
    """RDS 자동 백업 활성화 및 보존 기간 여부를 확인합니다."""
    instances = aws_config.get("rds", {}).get("db_instances", [])
    if not instances:
        return "NA", "RDS 인스턴스가 없습니다.", {}

    violations = [
        {"id": i["DBInstanceIdentifier"], "retention": i.get("BackupRetentionPeriod", 0)}
        for i in instances
        if i.get("BackupRetentionPeriod", 0) < RDS_BACKUP_MIN_DAYS
    ]

    if violations:
        return "FAIL", f"자동 백업 미설정 또는 보존 기간 {RDS_BACKUP_MIN_DAYS}일 미만 RDS 인스턴스 {len(violations)}개", {"violations": violations}
    return "PASS", f"모든 {len(instances)}개 RDS 인스턴스의 자동 백업이 활성화되어 있습니다.", {}


def _check_s3_versioning(aws_config: dict) -> tuple[str, str, dict]:
    """S3 버킷 버전 관리 활성화 여부를 확인합니다."""
    buckets = aws_config.get("s3", {}).get("buckets", [])
    versioning_map = aws_config.get("s3", {}).get("bucket_versioning", {})

    if not buckets:
        return "NA", "S3 버킷이 없습니다.", {}

    not_versioned = [
        b["Name"]
        for b in buckets
        if versioning_map.get(b["Name"], {}).get("Status") != "Enabled"
    ]

    if not_versioned:
        return "FAIL", f"버전 관리 비활성 S3 버킷 {len(not_versioned)}개: {', '.join(not_versioned)}", {"not_versioned": not_versioned}
    return "PASS", f"모든 {len(buckets)}개 S3 버킷에 버전 관리가 활성화되어 있습니다.", {}


def _check_rds_multi_az(aws_config: dict) -> tuple[str, str, dict]:
    """RDS Multi-AZ 배포 여부를 확인합니다."""
    instances = aws_config.get("rds", {}).get("db_instances", [])
    if not instances:
        return "NA", "RDS 인스턴스가 없습니다.", {}

    single_az = [i["DBInstanceIdentifier"] for i in instances if not i.get("MultiAZ")]

    if single_az:
        return "FAIL", f"Multi-AZ 미적용 RDS 인스턴스: {', '.join(single_az)}", {"single_az_instances": single_az}
    return "PASS", f"모든 {len(instances)}개 RDS 인스턴스가 Multi-AZ 배포로 구성되어 있습니다.", {}


def _check_rds_ssl_enforced(aws_config: dict) -> tuple[str, str, dict]:
    """RDS SSL/TLS 강제 적용 여부를 확인합니다."""
    instances = aws_config.get("rds", {}).get("db_instances", [])
    if not instances:
        return "NA", "RDS 인스턴스가 없습니다.", {}

    param_groups = aws_config.get("rds", {}).get("parameter_groups", {})
    if not param_groups:
        return "NA", "RDS 파라미터 그룹 정보가 없습니다. 수동으로 SSL 강제 적용 여부를 확인하세요.", {}

    not_enforced = []
    for inst in instances:
        pg_name = inst.get("DBParameterGroupName", "")
        params = param_groups.get(pg_name, {})
        # PostgreSQL: rds.force_ssl=1, MySQL: require_secure_transport=ON
        ssl_enforced = (
            params.get("rds.force_ssl") in ("1", 1)
            or params.get("require_secure_transport") in ("ON", "1", 1)
        )
        if not ssl_enforced:
            not_enforced.append(inst["DBInstanceIdentifier"])

    if not_enforced:
        return "FAIL", f"SSL/TLS 강제 적용이 미설정된 RDS 인스턴스: {', '.join(not_enforced)}", {"not_enforced": not_enforced}
    return "PASS", f"모든 {len(instances)}개 RDS 인스턴스에 SSL/TLS 강제 적용이 설정되어 있습니다.", {}


def _check_s3_cross_region_replication(aws_config: dict) -> tuple[str, str, dict]:
    """S3 교차 리전 복제 설정 여부를 확인합니다."""
    buckets = aws_config.get("s3", {}).get("buckets", [])
    if not buckets:
        return "NA", "S3 버킷이 없습니다.", {}
    # 교차 리전 복제는 선택 사항이며 모든 버킷에 필수가 아님 — 버킷이 존재하면 권장으로 PASS 처리
    return (
        "PASS",
        f"{len(buckets)}개 S3 버킷이 존재합니다. 중요 버킷의 교차 리전 복제 설정을 수동으로 검토하세요.",
        {"bucket_count": len(buckets), "note": "교차 리전 복제 설정은 수동 확인이 필요합니다."},
    )


# ---------------------------------------------------------------------------
# check_type 디스패치 맵
# ---------------------------------------------------------------------------

CHECK_HANDLERS = {
    "mfa_enabled":                   _check_mfa_enabled,
    "root_mfa":                      _check_root_mfa,
    "password_policy":               _check_password_policy,
    "access_key_age":                _check_access_key_age,
    "no_root_access_key":            _check_no_root_access_key,
    "vpc_isolation":                 _check_vpc_isolation,
    "sg_open_ingress":               _check_sg_open_ingress,
    "nacl_default_deny":             _check_nacl_default_deny,
    "sg_unrestricted_all":           _check_sg_unrestricted_all,
    "rds_not_public":                _check_rds_not_public,
    "s3_public_block":               _check_s3_public_block,
    "s3_acl_public_write":           _check_s3_acl_public_write,
    "s3_encryption":                 _check_s3_encryption,
    "rds_encryption":                _check_rds_encryption,
    "ebs_encryption":                _check_ebs_encryption,
    "elb_https_listener":            _check_elb_https_listener,
    "kms_key_rotation":              _check_kms_key_rotation,
    "kms_key_active":                _check_kms_key_active,
    "ssm_managed":                   _check_ssm_managed,
    "ssm_patch_compliance":          _check_ssm_patch_compliance,
    "cloudtrail_enabled":            _check_cloudtrail_enabled,
    "cloudtrail_encrypted":          _check_cloudtrail_encrypted,
    "cloudtrail_log_validation":     _check_cloudtrail_log_validation,
    "vpc_flow_logs":                 _check_vpc_flow_logs,
    "guardduty_enabled":             _check_guardduty_enabled,
    "guardduty_findings":            _check_guardduty_findings,
    "securityhub_enabled":           _check_securityhub_enabled,
    "cloudwatch_alarms":             _check_cloudwatch_alarms,
    "config_enabled":                _check_config_enabled,
    "cloudwatch_log_retention":      _check_cloudwatch_log_retention,
    "config_rules_compliant":        _check_config_rules_compliant,
    "inspector_enabled":             _check_inspector_enabled,
    "inspector_findings":            _check_inspector_findings,
    "rds_backup":                    _check_rds_backup,
    "s3_versioning":                 _check_s3_versioning,
    "rds_multi_az":                  _check_rds_multi_az,
    "s3_cross_region_replication":   _check_s3_cross_region_replication,
    "rds_ssl_enforced":              _check_rds_ssl_enforced,
}


# ---------------------------------------------------------------------------
# 퍼블릭 인터페이스
# ---------------------------------------------------------------------------

def evaluate(aws_config: dict, mapping: list | str | Path | dict | None = None) -> dict:
    """
    수집된 AWS 설정과 ISMS-P 매핑을 비교하여 충족/미충족 여부를 판정합니다.

    Parameters
    ----------
    aws_config : dict
        aws_checker.collect()가 반환한 AWS 설정 데이터
    mapping : list, optional
        isms_mapping.json 항목 목록. None이면 자동으로 로드합니다.

    Returns
    -------
    dict
        총계, 통과/실패 수, 항목별 결과, 카테고리별 집계를 포함하는 평가 결과
    """
    mapping = normalize_mapping(mapping)

    results = []
    by_category: dict[str, dict] = {}

    for item in mapping:
        item_id = item["id"]
        isms_p_id = item["isms_p_id"]
        check_type = item.get("check_type", "")
        handler = CHECK_HANDLERS.get(check_type)

        if handler is None:
            logger.warning("check_type '%s'에 대한 핸들러가 없습니다 (항목: %s).", check_type, item_id)
            status, evidence, details = "NA", f"check_type '{check_type}'에 대한 핸들러가 구현되지 않았습니다.", {}
        else:
            try:
                status, evidence, details = handler(aws_config)
            except Exception as exc:
                logger.exception("항목 %s 평가 중 오류 발생: %s", item_id, exc)
                status, evidence, details = "ERROR", str(exc), {}

        results.append({
            "id":           item_id,
            "isms_p_id":    isms_p_id,
            "isms_p_name":  item.get("isms_p_name", ""),
            "title":        item.get("title", ""),
            "status":       status,
            "severity":     item.get("severity", "MEDIUM"),
            "evidence":     evidence,
            "remediation":  item.get("remediation", ""),
            "details":      details,
        })

        # 카테고리별 집계
        if isms_p_id not in by_category:
            by_category[isms_p_id] = {"name": item.get("isms_p_name", ""), "total": 0, "passed": 0, "failed": 0, "na": 0, "error": 0}
        cat = by_category[isms_p_id]
        cat["total"] += 1
        if status == "PASS":
            cat["passed"] += 1
        elif status == "FAIL":
            cat["failed"] += 1
        elif status == "ERROR":
            cat["error"] += 1
        else:
            cat["na"] += 1

    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    na = sum(1 for r in results if r["status"] == "NA")
    error = sum(1 for r in results if r["status"] == "ERROR")

    checkable = total - na - error
    pass_rate = round((passed / checkable * 100), 1) if checkable > 0 else 0.0

    return {
        "total":      total,
        "passed":     passed,
        "failed":     failed,
        "na":         na,
        "error":      error,
        "pass_rate":  pass_rate,
        "items":      results,
        "by_category": by_category,
    }
