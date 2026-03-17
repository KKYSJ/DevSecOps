"""
ISMS-P 자동 점검 모듈 단위 테스트

pytest를 사용하여 evaluator, aws_checker, json_report 모듈을 검증합니다.
AWS 자격증명 없이 목업 데이터로 실행됩니다.
"""

import json
import os
import sys
import pytest
from pathlib import Path

# 프로젝트 루트를 PYTHONPATH에 추가
_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ismsp.checker.aws_checker import _mock_data, collect
from ismsp.checker.evaluator import load_mapping, evaluate
from ismsp.reporter.json_report import generate as generate_json, to_json_string


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def mock_aws_config():
    return _mock_data()


@pytest.fixture(scope="session")
def mapping():
    return load_mapping()


@pytest.fixture(scope="session")
def evaluation_result(mock_aws_config, mapping):
    return evaluate(mock_aws_config, mapping=mapping)


@pytest.fixture(scope="session")
def json_report_result(evaluation_result):
    return generate_json(evaluation_result)


# ---------------------------------------------------------------------------
# 매핑 파일 테스트
# ---------------------------------------------------------------------------

class TestMapping:
    def test_mapping_loads(self, mapping):
        assert mapping is not None
        assert isinstance(mapping, list)

    def test_mapping_has_38_items(self, mapping):
        assert len(mapping) >= 38, f"매핑 항목이 38개 미만입니다: {len(mapping)}개"

    def test_all_items_have_required_fields(self, mapping):
        required_fields = {"id", "isms_p_id", "isms_p_name", "title", "check_type", "severity", "remediation"}
        for item in mapping:
            missing = required_fields - item.keys()
            assert not missing, f"항목 {item.get('id')}에 필드 누락: {missing}"

    def test_all_ids_are_unique(self, mapping):
        ids = [item["id"] for item in mapping]
        assert len(ids) == len(set(ids)), "중복된 항목 ID가 있습니다."

    def test_isms_p_ids_are_valid_format(self, mapping):
        import re
        pattern = re.compile(r"^\d+\.\d+\.\d+$")
        for item in mapping:
            assert pattern.match(item["isms_p_id"]), f"유효하지 않은 isms_p_id: {item['isms_p_id']}"

    def test_severity_values_are_valid(self, mapping):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for item in mapping:
            assert item["severity"] in valid, f"유효하지 않은 severity: {item['severity']} (항목: {item['id']})"

    def test_coverage_of_required_categories(self, mapping):
        """필수 ISMS-P 카테고리가 매핑에 포함되어 있는지 확인합니다."""
        covered = {item["isms_p_id"] for item in mapping}
        required = {"2.5.1", "2.5.2", "2.6.1", "2.6.2", "2.6.7", "2.7.1", "2.8.1", "2.8.4",
                    "2.9.1", "2.10.1", "2.11.1", "2.12.1"}
        missing = required - covered
        assert not missing, f"누락된 ISMS-P 카테고리: {missing}"


# ---------------------------------------------------------------------------
# AWS 수집기 테스트
# ---------------------------------------------------------------------------

class TestAWSChecker:
    def test_mock_data_returns_dict(self, mock_aws_config):
        assert isinstance(mock_aws_config, dict)

    def test_mock_data_has_all_services(self, mock_aws_config):
        required_services = {"iam", "ec2", "s3", "rds", "cloudtrail", "guardduty",
                             "securityhub", "cloudwatch", "config", "kms", "ssm", "inspector", "elbv2"}
        missing = required_services - mock_aws_config.keys()
        assert not missing, f"목업 데이터에 누락된 서비스: {missing}"

    def test_mock_iam_has_users(self, mock_aws_config):
        users = mock_aws_config["iam"].get("users", [])
        assert len(users) > 0

    def test_mock_iam_has_password_policy(self, mock_aws_config):
        policy = mock_aws_config["iam"].get("password_policy")
        assert policy is not None

    def test_mock_ec2_has_vpcs_and_subnets(self, mock_aws_config):
        assert len(mock_aws_config["ec2"].get("vpcs", [])) > 0
        assert len(mock_aws_config["ec2"].get("subnets", [])) > 0

    def test_mock_s3_has_buckets(self, mock_aws_config):
        assert len(mock_aws_config["s3"].get("buckets", [])) > 0

    def test_mock_rds_has_instances(self, mock_aws_config):
        assert len(mock_aws_config["rds"].get("db_instances", [])) > 0

    def test_collect_without_credentials_returns_mock(self):
        """AWS 자격증명 없는 환경에서 collect()가 목업 데이터를 반환하는지 확인합니다."""
        # 자격증명 환경 변수를 임시로 무효화
        env_backup = {}
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                    "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
            env_backup[key] = os.environ.pop(key, None)

        try:
            result = collect(region="ap-northeast-2")
            assert isinstance(result, dict)
            assert "iam" in result
        finally:
            for key, val in env_backup.items():
                if val is not None:
                    os.environ[key] = val


# ---------------------------------------------------------------------------
# 평가 엔진 테스트
# ---------------------------------------------------------------------------

class TestEvaluator:
    def test_evaluate_returns_dict(self, evaluation_result):
        assert isinstance(evaluation_result, dict)

    def test_evaluate_has_required_keys(self, evaluation_result):
        required = {"total", "passed", "failed", "na", "pass_rate", "items", "by_category"}
        missing = required - evaluation_result.keys()
        assert not missing, f"평가 결과에 누락된 키: {missing}"

    def test_evaluate_total_matches_item_count(self, evaluation_result):
        assert evaluation_result["total"] == len(evaluation_result["items"])

    def test_evaluate_counts_are_consistent(self, evaluation_result):
        items = evaluation_result["items"]
        assert evaluation_result["passed"] == sum(1 for i in items if i["status"] == "PASS")
        assert evaluation_result["failed"] == sum(1 for i in items if i["status"] == "FAIL")
        assert evaluation_result["na"] == sum(1 for i in items if i["status"] == "NA")

    def test_pass_rate_is_between_0_and_100(self, evaluation_result):
        assert 0 <= evaluation_result["pass_rate"] <= 100

    def test_all_items_have_status(self, evaluation_result):
        valid_statuses = {"PASS", "FAIL", "NA", "ERROR"}
        for item in evaluation_result["items"]:
            assert item["status"] in valid_statuses, f"유효하지 않은 상태: {item['status']} ({item['id']})"

    def test_all_items_have_evidence(self, evaluation_result):
        for item in evaluation_result["items"]:
            assert item.get("evidence"), f"증거 정보가 없는 항목: {item['id']}"

    def test_by_category_covers_all_items(self, evaluation_result):
        items = evaluation_result["items"]
        cat_totals = sum(c["total"] for c in evaluation_result["by_category"].values())
        assert cat_totals == evaluation_result["total"]

    # 개별 check_type 결과 검증 (목업 데이터 기반 예상 결과)

    def test_root_mfa_passes(self, evaluation_result):
        """목업 데이터에서 루트 MFA가 활성화되어 있으므로 PASS여야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.5.1-02")
        assert item["status"] == "PASS"

    def test_root_access_key_passes(self, evaluation_result):
        """목업 데이터에서 루트 액세스 키가 없으므로 PASS여야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.5.2-02")
        assert item["status"] == "PASS"

    def test_mfa_enabled_fails(self, evaluation_result):
        """목업 데이터에 MFA 미설정 사용자가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.5.1-01")
        assert item["status"] == "FAIL"

    def test_access_key_age_fails(self, evaluation_result):
        """목업 데이터에 90일 초과 액세스 키가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.5.2-01")
        assert item["status"] == "FAIL"

    def test_sg_open_ingress_fails(self, evaluation_result):
        """목업 데이터에 0.0.0.0/0 SSH/RDP 허용 SG가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.6.1-02")
        assert item["status"] == "FAIL"

    def test_rds_not_public_fails(self, evaluation_result):
        """목업 데이터에 퍼블릭 접근 허용 RDS가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.6.2-01")
        assert item["status"] == "FAIL"

    def test_s3_public_block_fails(self, evaluation_result):
        """목업 데이터에 퍼블릭 접근 차단 미설정 S3가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.6.2-02")
        assert item["status"] == "FAIL"

    def test_ebs_encryption_passes(self, evaluation_result):
        """목업 데이터에서 EBS 기본 암호화가 활성화되어 있으므로 PASS여야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.6.7-03")
        assert item["status"] == "PASS"

    def test_cloudtrail_enabled_passes(self, evaluation_result):
        """목업 데이터에서 CloudTrail이 활성화되어 있으므로 PASS여야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.8.4-01")
        assert item["status"] == "PASS"

    def test_guardduty_enabled_passes(self, evaluation_result):
        """목업 데이터에서 GuardDuty가 활성화되어 있으므로 PASS여야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.9.1-01")
        assert item["status"] == "PASS"

    def test_kms_rotation_fails(self, evaluation_result):
        """목업 데이터에 키 교체 미설정 KMS 키가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.7.1-01")
        assert item["status"] == "FAIL"

    def test_rds_backup_fails(self, evaluation_result):
        """목업 데이터에 백업 보존 기간 미달 RDS가 있으므로 FAIL이어야 합니다."""
        item = next(i for i in evaluation_result["items"] if i["id"] == "ISMS-2.12.1-01")
        assert item["status"] == "FAIL"


# ---------------------------------------------------------------------------
# JSON 보고서 테스트
# ---------------------------------------------------------------------------

class TestJSONReport:
    def test_generate_returns_dict(self, json_report_result):
        assert isinstance(json_report_result, dict)

    def test_report_type_is_isms_p(self, json_report_result):
        assert json_report_result["report_type"] == "isms_p"

    def test_report_has_generated_at(self, json_report_result):
        assert "generated_at" in json_report_result
        assert json_report_result["generated_at"]

    def test_report_summary_has_required_fields(self, json_report_result):
        summary = json_report_result["summary"]
        for field in ("total", "passed", "failed", "pass_rate", "critical_failures"):
            assert field in summary, f"summary에 '{field}' 필드가 없습니다."

    def test_report_items_list_present(self, json_report_result):
        assert "items" in json_report_result
        assert isinstance(json_report_result["items"], list)

    def test_report_by_category_present(self, json_report_result):
        assert "by_category" in json_report_result
        assert isinstance(json_report_result["by_category"], dict)

    def test_critical_failures_are_high_severity(self, json_report_result):
        for cf in json_report_result["summary"]["critical_failures"]:
            assert cf["severity"] in ("CRITICAL", "HIGH")

    def test_report_is_json_serializable(self, json_report_result):
        json_str = to_json_string(json_report_result)
        parsed = json.loads(json_str)
        assert parsed["report_type"] == "isms_p"

    def test_metadata_mentions_manual_items(self, json_report_result):
        metadata = json_report_result.get("metadata", {})
        assert metadata.get("manual_check_items") == 64
        assert metadata.get("total_isms_p_items") == 102


# ---------------------------------------------------------------------------
# 통합 테스트
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_full_pipeline_runs_without_error(self):
        """전체 파이프라인이 오류 없이 실행되는지 확인합니다."""
        from ismsp.main import run
        result = run(region="ap-northeast-2")
        assert isinstance(result, dict)
        assert result["total"] >= 38

    def test_pipeline_produces_valid_pass_rate(self):
        """파이프라인이 유효한 통과율을 반환하는지 확인합니다."""
        from ismsp.main import run
        result = run()
        assert 0 <= result["pass_rate"] <= 100

    def test_json_report_saved_to_file(self, tmp_path, evaluation_result):
        """JSON 보고서가 파일로 저장되는지 확인합니다."""
        from ismsp.reporter.json_report import generate, save
        report = generate(evaluation_result)
        output_path = str(tmp_path / "test_report.json")
        saved = save(report, output_path)
        assert os.path.isfile(saved)
        with open(saved, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["report_type"] == "isms_p"
