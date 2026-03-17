"""
ISMS-P AWS 설정 데이터 수집 모듈

boto3를 사용하여 ISMS-P 38개 자동 점검 항목에 필요한 AWS 설정 정보를 수집합니다.
AWS 자격증명이 없는 로컬 개발 환경에서는 데모용 목업(mock) 데이터를 반환합니다.
"""

import boto3
import logging
import os
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError, NoCredentialsError, EndpointResolutionError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mock data (로컬 개발 / CI 환경에서 AWS 자격증명 없이 실행 시 사용)
# ---------------------------------------------------------------------------

def _mock_data() -> dict:
    """데모/테스트용 목업 AWS 설정 데이터를 반환합니다."""
    now = datetime.now(timezone.utc)
    old_key_date = now - timedelta(days=120)
    recent_key_date = now - timedelta(days=30)

    return {
        "iam": {
            "account_summary": {
                "AccountMFAEnabled": 1,
                "AccountAccessKeysPresent": 0,
                "MFADevicesInUse": 3,
                "Users": 5,
            },
            "users": [
                {"UserName": "alice", "UserId": "AIDA1", "Arn": "arn:aws:iam::123456789012:user/alice"},
                {"UserName": "bob",   "UserId": "AIDA2", "Arn": "arn:aws:iam::123456789012:user/bob"},
                {"UserName": "carol", "UserId": "AIDA3", "Arn": "arn:aws:iam::123456789012:user/carol"},
                {"UserName": "dave",  "UserId": "AIDA4", "Arn": "arn:aws:iam::123456789012:user/dave"},
                {"UserName": "eve",   "UserId": "AIDA5", "Arn": "arn:aws:iam::123456789012:user/eve"},
            ],
            "mfa_by_user": {
                "alice": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/alice", "EnableDate": now.isoformat()}],
                "bob":   [{"SerialNumber": "arn:aws:iam::123456789012:mfa/bob",   "EnableDate": now.isoformat()}],
                "carol": [],   # MFA 미설정
                "dave":  [{"SerialNumber": "arn:aws:iam::123456789012:mfa/dave",  "EnableDate": now.isoformat()}],
                "eve":   [],   # MFA 미설정
            },
            "password_policy": {
                "MinimumPasswordLength": 12,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 5,
                "HardExpiry": False,
            },
            "access_keys": {
                "alice": [{"AccessKeyId": "AKIA1", "Status": "Active",   "CreateDate": recent_key_date.isoformat()}],
                "bob":   [{"AccessKeyId": "AKIA2", "Status": "Active",   "CreateDate": old_key_date.isoformat()}],  # 90일 초과
                "carol": [],
                "dave":  [{"AccessKeyId": "AKIA3", "Status": "Inactive", "CreateDate": old_key_date.isoformat()}],
                "eve":   [],
            },
        },
        "ec2": {
            "vpcs": [
                {"VpcId": "vpc-aaa111", "IsDefault": False, "CidrBlock": "10.0.0.0/16"},
                {"VpcId": "vpc-bbb222", "IsDefault": True,  "CidrBlock": "172.31.0.0/16"},
            ],
            "subnets": [
                {"SubnetId": "subnet-pub1",  "VpcId": "vpc-aaa111", "MapPublicIpOnLaunch": True,  "AvailabilityZone": "ap-northeast-2a"},
                {"SubnetId": "subnet-pub2",  "VpcId": "vpc-aaa111", "MapPublicIpOnLaunch": True,  "AvailabilityZone": "ap-northeast-2c"},
                {"SubnetId": "subnet-prv1",  "VpcId": "vpc-aaa111", "MapPublicIpOnLaunch": False, "AvailabilityZone": "ap-northeast-2a"},
                {"SubnetId": "subnet-prv2",  "VpcId": "vpc-aaa111", "MapPublicIpOnLaunch": False, "AvailabilityZone": "ap-northeast-2c"},
                {"SubnetId": "subnet-def1",  "VpcId": "vpc-bbb222", "MapPublicIpOnLaunch": True,  "AvailabilityZone": "ap-northeast-2a"},
            ],
            "security_groups": [
                {
                    "GroupId": "sg-safe001",
                    "GroupName": "app-sg",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"IpProtocol": "tcp", "FromPort": 22,  "ToPort": 22,
                         "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
                    ],
                },
                {
                    "GroupId": "sg-open002",
                    "GroupName": "bad-sg",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 22,  "ToPort": 22,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},   # 위반: SSH 전체 허용
                        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},   # 위반: RDP 전체 허용
                    ],
                },
                {
                    "GroupId": "sg-all003",
                    "GroupName": "all-open-sg",
                    "IpPermissions": [
                        {"IpProtocol": "-1",
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},   # 위반: All traffic
                    ],
                },
            ],
            "network_acls": [
                {
                    "NetworkAclId": "acl-001",
                    "VpcId": "vpc-aaa111",
                    "IsDefault": True,
                    "Entries": [
                        {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
                        {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny",  "Egress": False, "CidrBlock": "0.0.0.0/0"},
                    ],
                },
            ],
            "ebs_encryption_by_default": True,
            "flow_logs": [
                {"FlowLogId": "fl-001", "ResourceId": "vpc-aaa111", "FlowLogStatus": "ACTIVE", "TrafficType": "ALL"},
            ],
            "instances": [
                {"InstanceId": "i-001", "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "web-server"}]},
                {"InstanceId": "i-002", "State": {"Name": "running"}, "Tags": [{"Key": "Name", "Value": "app-server"}]},
            ],
        },
        "s3": {
            "buckets": [
                {"Name": "my-app-logs",    "CreationDate": "2023-01-01T00:00:00+00:00"},
                {"Name": "my-app-backups", "CreationDate": "2023-01-01T00:00:00+00:00"},
                {"Name": "my-app-assets",  "CreationDate": "2023-01-01T00:00:00+00:00"},
            ],
            "bucket_encryption": {
                "my-app-logs":    {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
                "my-app-backups": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "key-001"}}]}},
                "my-app-assets":  None,  # 암호화 미설정
            },
            "public_access_block": {
                "my-app-logs":    {"BlockPublicAcls": True,  "IgnorePublicAcls": True,  "BlockPublicPolicy": True,  "RestrictPublicBuckets": True},
                "my-app-backups": {"BlockPublicAcls": True,  "IgnorePublicAcls": True,  "BlockPublicPolicy": True,  "RestrictPublicBuckets": True},
                "my-app-assets":  {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},  # 위반
            },
            "bucket_versioning": {
                "my-app-logs":    {"Status": "Enabled"},
                "my-app-backups": {"Status": "Enabled"},
                "my-app-assets":  {"Status": "Suspended"},  # 비활성
            },
            "bucket_acl": {
                "my-app-logs":    {"Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]},
                "my-app-backups": {"Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]},
                "my-app-assets":  {"Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]},
            },
        },
        "rds": {
            "db_instances": [
                {
                    "DBInstanceIdentifier": "prod-mysql",
                    "DBInstanceClass": "db.t3.medium",
                    "Engine": "mysql",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 7,
                    "MultiAZ": True,
                    "DBInstanceStatus": "available",
                    "DBParameterGroupName": "mysql-prod-pg",
                },
                {
                    "DBInstanceIdentifier": "dev-postgres",
                    "DBInstanceClass": "db.t3.micro",
                    "Engine": "postgres",
                    "PubliclyAccessible": True,   # 위반: 퍼블릭 접근
                    "StorageEncrypted": False,    # 위반: 암호화 미적용
                    "BackupRetentionPeriod": 1,   # 위반: 백업 보존 기간 부족
                    "MultiAZ": False,
                    "DBInstanceStatus": "available",
                    "DBParameterGroupName": "postgres-dev-pg",
                },
            ],
            "parameter_groups": {
                "mysql-prod-pg":   {"require_secure_transport": "ON"},
                "postgres-dev-pg": {"rds.force_ssl": "0"},  # 위반: SSL 미강제
            },
        },
        "cloudtrail": {
            "trails": [
                {
                    "Name": "main-trail",
                    "S3BucketName": "my-app-logs",
                    "IncludeGlobalServiceEvents": True,
                    "IsMultiRegionTrail": True,
                    "HasCustomEventSelectors": True,
                    "LogFileValidationEnabled": True,
                    "KMSKeyId": "arn:aws:kms:ap-northeast-2:123456789012:key/key-001",
                    "TrailARN": "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/main-trail",
                },
            ],
            "trail_status": {
                "main-trail": {
                    "IsLogging": True,
                    "LatestDeliveryTime": now.isoformat(),
                },
            },
        },
        "guardduty": {
            "detectors": ["abcd1234efgh5678ijkl9012"],
            "detector_details": {
                "abcd1234efgh5678ijkl9012": {
                    "Status": "ENABLED",
                    "FindingPublishingFrequency": "SIX_HOURS",
                    "ServiceRole": "arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                },
            },
            "findings": [],  # 위협 없음
        },
        "securityhub": {
            "hub_arn": "arn:aws:securityhub:ap-northeast-2:123456789012:hub/default",
            "subscribed_standards": [
                {"StandardsArn": "arn:aws:securityhub:ap-northeast-2::standards/aws-foundational-security-best-practices/v/1.0.0", "StandardsStatus": "READY"},
            ],
        },
        "cloudwatch": {
            "alarms": [
                {"AlarmName": "RootAccountUsage",        "MetricName": "RootAccountUsage",        "StateValue": "OK", "ActionsEnabled": True},
                {"AlarmName": "UnauthorizedAPICalls",    "MetricName": "UnauthorizedAPICalls",    "StateValue": "OK", "ActionsEnabled": True},
                {"AlarmName": "IAMPolicyChanges",        "MetricName": "IAMPolicyChanges",        "StateValue": "OK", "ActionsEnabled": True},
                {"AlarmName": "CloudTrailChanges",       "MetricName": "CloudTrailChanges",       "StateValue": "OK", "ActionsEnabled": True},
                {"AlarmName": "SecurityGroupChanges",    "MetricName": "SecurityGroupChanges",    "StateValue": "OK", "ActionsEnabled": True},
            ],
            "log_groups": [
                {"logGroupName": "/aws/cloudtrail/main",          "retentionInDays": 365},
                {"logGroupName": "/aws/lambda/my-function",       "retentionInDays": 90},
                {"logGroupName": "/aws/rds/instance/prod-mysql",  "retentionInDays": None},  # 보존 기간 미설정
            ],
        },
        "config": {
            "configuration_recorders": [
                {
                    "name": "default",
                    "roleARN": "arn:aws:iam::123456789012:role/config-role",
                    "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True},
                }
            ],
            "recorder_statuses": [
                {"name": "default", "recording": True, "lastStatus": "SUCCESS"},
            ],
            "compliance_summary": {
                "compliant_rules": 45,
                "non_compliant_rules": 3,
            },
        },
        "kms": {
            "keys": [
                {"KeyId": "key-001", "KeyArn": "arn:aws:kms:ap-northeast-2:123456789012:key/key-001"},
                {"KeyId": "key-002", "KeyArn": "arn:aws:kms:ap-northeast-2:123456789012:key/key-002"},
            ],
            "key_details": {
                "key-001": {"KeyMetadata": {"KeyId": "key-001", "KeyState": "Enabled",  "KeyManager": "CUSTOMER", "Description": "Main encryption key"}},
                "key-002": {"KeyMetadata": {"KeyId": "key-002", "KeyState": "Enabled",  "KeyManager": "CUSTOMER", "Description": "Backup encryption key"}},
            },
            "rotation_status": {
                "key-001": {"KeyRotationEnabled": True},
                "key-002": {"KeyRotationEnabled": False},  # 위반: 키 교체 미설정
            },
        },
        "ssm": {
            "managed_instances": [
                {"InstanceId": "i-001", "PingStatus": "Online",  "PlatformName": "Amazon Linux",  "AgentVersion": "3.2.0"},
                {"InstanceId": "i-002", "PingStatus": "Online",  "PlatformName": "Amazon Linux",  "AgentVersion": "3.2.0"},
            ],
            "patch_states": [
                {"InstanceId": "i-001", "MissingCount": 0, "FailedCount": 0, "InstalledOtherCount": 2, "PatchGroup": "production"},
                {"InstanceId": "i-002", "MissingCount": 2, "FailedCount": 0, "InstalledOtherCount": 5, "PatchGroup": "production"},  # 위반: 미패치
            ],
        },
        "inspector": {
            "enabled": True,
            "account_status": [{"accountId": "123456789012", "state": {"status": "ENABLED"}}],
            "findings": [],
        },
        "elbv2": {
            "load_balancers": [
                {"LoadBalancerArn": "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/my-alb/abc123", "DNSName": "my-alb.ap-northeast-2.elb.amazonaws.com", "Type": "application"},
            ],
            "listeners": {
                "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/my-alb/abc123": [
                    {"ListenerArn": "arn:...:listener/app/my-alb/abc/1", "Protocol": "HTTPS", "Port": 443},
                    {"ListenerArn": "arn:...:listener/app/my-alb/abc/2", "Protocol": "HTTP",  "Port": 80},
                ],
            },
        },
    }


# ---------------------------------------------------------------------------
# AWS 서비스별 데이터 수집 함수
# ---------------------------------------------------------------------------

def _safe_call(client, method_name: str, result_key: str = None, default=None, **kwargs):
    """boto3 클라이언트 메서드를 안전하게 호출하고 예외 발생 시 기본값을 반환합니다."""
    try:
        method = getattr(client, method_name)
        response = method(**kwargs)
        response.pop("ResponseMetadata", None)
        if result_key:
            return response.get(result_key, default if default is not None else [])
        return response
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        logger.warning("boto3 ClientError [%s.%s]: %s", client.meta.service_model.service_name, method_name, code)
        return default if default is not None else {}
    except Exception as exc:
        logger.warning("boto3 호출 실패 [%s.%s]: %s", client.meta.service_model.service_name, method_name, exc)
        return default if default is not None else {}


def _collect_iam(session) -> dict:
    iam = session.client("iam")

    account_summary = _safe_call(iam, "get_account_summary", "SummaryMap", default={})

    users = _safe_call(iam, "list_users", "Users", default=[])

    password_policy = _safe_call(iam, "get_account_password_policy", "PasswordPolicy", default=None)

    mfa_by_user = {}
    for user in users:
        username = user["UserName"]
        devices = _safe_call(iam, "list_mfa_devices", "MFADevices", default=[], UserName=username)
        mfa_by_user[username] = devices

    access_keys = {}
    for user in users:
        username = user["UserName"]
        keys = _safe_call(iam, "list_access_keys", "AccessKeyMetadata", default=[], UserName=username)
        access_keys[username] = keys

    return {
        "account_summary": account_summary,
        "users": users,
        "mfa_by_user": mfa_by_user,
        "password_policy": password_policy,
        "access_keys": access_keys,
    }


def _collect_ec2(session, region: str) -> dict:
    ec2 = session.client("ec2", region_name=region)

    vpcs = _safe_call(ec2, "describe_vpcs", "Vpcs", default=[])
    subnets = _safe_call(ec2, "describe_subnets", "Subnets", default=[])
    security_groups = _safe_call(ec2, "describe_security_groups", "SecurityGroups", default=[])
    network_acls = _safe_call(ec2, "describe_network_acls", "NetworkAcls", default=[])
    flow_logs = _safe_call(ec2, "describe_flow_logs", "FlowLogs", default=[])

    ebs_enc_response = _safe_call(ec2, "get_ebs_encryption_by_default", default={})
    ebs_encryption_by_default = ebs_enc_response.get("EbsEncryptionByDefault", False) if ebs_enc_response else False

    instances_response = _safe_call(ec2, "describe_instances", "Reservations", default=[])
    instances = []
    for reservation in instances_response:
        for inst in reservation.get("Instances", []):
            instances.append(inst)

    return {
        "vpcs": vpcs,
        "subnets": subnets,
        "security_groups": security_groups,
        "network_acls": network_acls,
        "flow_logs": flow_logs,
        "ebs_encryption_by_default": ebs_encryption_by_default,
        "instances": instances,
    }


def _collect_s3(session) -> dict:
    s3 = session.client("s3")

    buckets = _safe_call(s3, "list_buckets", "Buckets", default=[])

    bucket_encryption = {}
    public_access_block = {}
    bucket_versioning = {}
    bucket_acl = {}

    for bucket in buckets:
        name = bucket["Name"]

        enc = _safe_call(s3, "get_bucket_encryption", default=None, Bucket=name)
        bucket_encryption[name] = enc

        pab = _safe_call(s3, "get_public_access_block", "PublicAccessBlockConfiguration", default=None, Bucket=name)
        public_access_block[name] = pab

        ver = _safe_call(s3, "get_bucket_versioning", default={}, Bucket=name)
        bucket_versioning[name] = ver

        acl = _safe_call(s3, "get_bucket_acl", default={}, Bucket=name)
        bucket_acl[name] = acl

    return {
        "buckets": buckets,
        "bucket_encryption": bucket_encryption,
        "public_access_block": public_access_block,
        "bucket_versioning": bucket_versioning,
        "bucket_acl": bucket_acl,
    }


def _collect_rds(session, region: str) -> dict:
    rds = session.client("rds", region_name=region)
    db_instances = _safe_call(rds, "describe_db_instances", "DBInstances", default=[])
    return {"db_instances": db_instances}


def _collect_cloudtrail(session, region: str) -> dict:
    ct = session.client("cloudtrail", region_name=region)
    trails_raw = _safe_call(ct, "describe_trails", "trailList", default=[])

    trail_status = {}
    for trail in trails_raw:
        trail_name = trail.get("Name", "")
        status = _safe_call(ct, "get_trail_status", default={}, Name=trail_name)
        trail_status[trail_name] = status

    return {"trails": trails_raw, "trail_status": trail_status}


def _collect_guardduty(session, region: str) -> dict:
    gd = session.client("guardduty", region_name=region)
    detectors = _safe_call(gd, "list_detectors", "DetectorIds", default=[])

    detector_details = {}
    findings = []

    for detector_id in detectors:
        details = _safe_call(gd, "get_detector", default={}, DetectorId=detector_id)
        detector_details[detector_id] = details

        finding_ids = _safe_call(
            gd, "list_findings", "FindingIds", default=[],
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"severity": {"Gte": 7}}}
        )
        findings.extend(finding_ids)

    return {
        "detectors": detectors,
        "detector_details": detector_details,
        "findings": findings,
    }


def _collect_securityhub(session, region: str) -> dict:
    hub = session.client("securityhub", region_name=region)
    hub_info = _safe_call(hub, "describe_hub", default=None)
    if hub_info is None:
        return {"hub_arn": None, "subscribed_standards": []}

    standards = _safe_call(hub, "get_enabled_standards", "StandardsSubscriptions", default=[])
    return {
        "hub_arn": hub_info.get("HubArn"),
        "subscribed_standards": standards,
    }


def _collect_cloudwatch(session, region: str) -> dict:
    cw = session.client("cloudwatch", region_name=region)
    alarms = _safe_call(cw, "describe_alarms", "MetricAlarms", default=[])

    logs_client = session.client("logs", region_name=region)
    log_groups = _safe_call(logs_client, "describe_log_groups", "logGroups", default=[])

    return {"alarms": alarms, "log_groups": log_groups}


def _collect_config(session, region: str) -> dict:
    cfg = session.client("config", region_name=region)

    recorders = _safe_call(cfg, "describe_configuration_recorders", "ConfigurationRecorders", default=[])
    recorder_statuses = _safe_call(cfg, "describe_configuration_recorder_status", "ConfigurationRecordersStatus", default=[])

    compliance = _safe_call(
        cfg, "get_compliance_summary_by_config_rule",
        "ComplianceSummary", default={}
    )

    return {
        "configuration_recorders": recorders,
        "recorder_statuses": recorder_statuses,
        "compliance_summary": compliance,
    }


def _collect_kms(session, region: str) -> dict:
    kms_client = session.client("kms", region_name=region)
    keys = _safe_call(kms_client, "list_keys", "Keys", default=[])

    key_details = {}
    rotation_status = {}

    for key in keys:
        key_id = key["KeyId"]
        details = _safe_call(kms_client, "describe_key", default={}, KeyId=key_id)
        key_details[key_id] = details

        metadata = details.get("KeyMetadata", {})
        if metadata.get("KeyManager") == "CUSTOMER" and metadata.get("KeyState") == "Enabled":
            rot = _safe_call(kms_client, "get_key_rotation_status", default={}, KeyId=key_id)
            rotation_status[key_id] = rot

    return {
        "keys": keys,
        "key_details": key_details,
        "rotation_status": rotation_status,
    }


def _collect_ssm(session, region: str) -> dict:
    ssm_client = session.client("ssm", region_name=region)
    managed_instances = _safe_call(ssm_client, "describe_instance_information", "InstanceInformationList", default=[])
    patch_states = _safe_call(ssm_client, "describe_instance_patch_states", "InstancePatchStates", default=[])
    return {"managed_instances": managed_instances, "patch_states": patch_states}


def _collect_inspector(session, region: str) -> dict:
    inspector = session.client("inspector2", region_name=region)
    account_status = _safe_call(inspector, "batch_get_account_status", "accounts", default=[],
                                 accountIds=["self"])  # 실제 계정 ID 필요 시 STS에서 조회
    if not account_status:
        return {"enabled": False, "account_status": [], "findings": []}

    enabled = any(
        a.get("state", {}).get("status") == "ENABLED"
        for a in account_status
    )

    findings_response = _safe_call(
        inspector, "list_findings", "findings", default=[],
        filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                        "severity":      [{"comparison": "EQUALS", "value": "CRITICAL"},
                                          {"comparison": "EQUALS", "value": "HIGH"}]}
    )

    return {
        "enabled": enabled,
        "account_status": account_status,
        "findings": findings_response,
    }


def _collect_elbv2(session, region: str) -> dict:
    elb = session.client("elbv2", region_name=region)
    load_balancers = _safe_call(elb, "describe_load_balancers", "LoadBalancers", default=[])

    listeners = {}
    for lb in load_balancers:
        arn = lb["LoadBalancerArn"]
        lb_listeners = _safe_call(elb, "describe_listeners", "Listeners", default=[], LoadBalancerArn=arn)
        listeners[arn] = lb_listeners

    return {"load_balancers": load_balancers, "listeners": listeners}


# ---------------------------------------------------------------------------
# 퍼블릭 인터페이스
# ---------------------------------------------------------------------------

def collect(region: str = None) -> dict:
    """
    ISMS-P 점검에 필요한 AWS 설정 데이터를 수집합니다.

    Parameters
    ----------
    region : str, optional
        AWS 리전 (기본값: 환경 변수 AWS_DEFAULT_REGION 또는 'ap-northeast-2')

    Returns
    -------
    dict
        서비스별로 수집된 AWS 설정 데이터
    """
    if region is None:
        region = os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-2")

    # AWS 자격증명 확인
    try:
        session = boto3.Session()
        sts = session.client("sts", region_name=region)
        sts.get_caller_identity()
        logger.info("AWS 자격증명 확인 완료. 실제 AWS 데이터를 수집합니다.")
    except (NoCredentialsError, ClientError, EndpointResolutionError, Exception) as exc:
        logger.warning("AWS 자격증명을 찾을 수 없거나 인증에 실패했습니다: %s", exc)
        logger.info("데모 목업 데이터를 사용합니다.")
        return _mock_data()

    # 실제 데이터 수집
    result = {}
    logger.info("IAM 데이터 수집 중...")
    result["iam"] = _collect_iam(session)

    logger.info("EC2 데이터 수집 중 (region=%s)...", region)
    result["ec2"] = _collect_ec2(session, region)

    logger.info("S3 데이터 수집 중...")
    result["s3"] = _collect_s3(session)

    logger.info("RDS 데이터 수집 중 (region=%s)...", region)
    result["rds"] = _collect_rds(session, region)

    logger.info("CloudTrail 데이터 수집 중 (region=%s)...", region)
    result["cloudtrail"] = _collect_cloudtrail(session, region)

    logger.info("GuardDuty 데이터 수집 중 (region=%s)...", region)
    result["guardduty"] = _collect_guardduty(session, region)

    logger.info("SecurityHub 데이터 수집 중 (region=%s)...", region)
    result["securityhub"] = _collect_securityhub(session, region)

    logger.info("CloudWatch 데이터 수집 중 (region=%s)...", region)
    result["cloudwatch"] = _collect_cloudwatch(session, region)

    logger.info("AWS Config 데이터 수집 중 (region=%s)...", region)
    result["config"] = _collect_config(session, region)

    logger.info("KMS 데이터 수집 중 (region=%s)...", region)
    result["kms"] = _collect_kms(session, region)

    logger.info("SSM 데이터 수집 중 (region=%s)...", region)
    result["ssm"] = _collect_ssm(session, region)

    logger.info("Inspector 데이터 수집 중 (region=%s)...", region)
    result["inspector"] = _collect_inspector(session, region)

    logger.info("ELB 데이터 수집 중 (region=%s)...", region)
    result["elbv2"] = _collect_elbv2(session, region)

    logger.info("AWS 데이터 수집 완료.")
    return result
