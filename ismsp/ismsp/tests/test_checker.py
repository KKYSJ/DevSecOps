"""
test_checker.py
────────────────
aws_checker + evaluator 단위 테스트 (Mock — 실제 AWS 불필요)

실행:
    cd secureflow/
    python -m unittest ismsp/tests/test_checker.py -v
"""

import sys, json, unittest
from pathlib import Path
from unittest.mock import MagicMock

if "botocore" not in sys.modules:
    bc = MagicMock()
    bc.exceptions.ClientError = Exception
    sys.modules["botocore"] = bc
    sys.modules["botocore.exceptions"] = bc.exceptions

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ismsp.checker.aws_checker import AWSChecker, ComplianceStatus, CheckResult
from ismsp.checker.evaluator   import Evaluator, ItemResult, _BOTO3_ONLY_CHECKS


def _session(iam_mfa=1, iam_keys=0):
    s = MagicMock()
    iam = MagicMock()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": iam_mfa, "AccountAccessKeysPresent": iam_keys}
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:test"}
    s.client.side_effect = lambda svc, **kw: {"iam": iam, "sts": sts}.get(svc, MagicMock())
    return s


# ── AWSChecker ────────────────────────────────────────────────────────────────

class TestAWSCheckerBoto3(unittest.TestCase):

    def test_iam_mfa_enabled(self):
        checker = AWSChecker(_session(iam_mfa=1, iam_keys=0))
        status, reason = checker._check_iam_account_summary()
        self.assertEqual(status, ComplianceStatus.COMPLIANT)
        self.assertIsNone(reason)

    def test_iam_mfa_disabled(self):
        checker = AWSChecker(_session(iam_mfa=0, iam_keys=1))
        status, reason = checker._check_iam_account_summary()
        self.assertEqual(status, ComplianceStatus.NON_COMPLIANT)
        self.assertIn("MFA", reason)

    def test_backup_plans_exist(self):
        s = MagicMock()
        backup = MagicMock()
        backup.list_backup_plans.return_value = {"BackupPlansList": [{"id": "p1"}]}
        backup.list_backup_vaults.return_value = {"BackupVaultList": [{"name": "Default"}]}
        s.client.return_value = backup
        checker = AWSChecker(s)
        status, _ = checker._check_backup_plans()
        self.assertEqual(status, ComplianceStatus.COMPLIANT)

    def test_backup_no_plans(self):
        s = MagicMock()
        backup = MagicMock()
        backup.list_backup_plans.return_value = {"BackupPlansList": []}
        backup.list_backup_vaults.return_value = {"BackupVaultList": []}
        s.client.return_value = backup
        checker = AWSChecker(s)
        status, reason = checker._check_backup_plans()
        self.assertEqual(status, ComplianceStatus.NON_COMPLIANT)

    def test_sh_disabled_falls_back(self):
        s = MagicMock()
        checker = AWSChecker(s)
        checker._sh_enabled = False
        results, remaining = checker._collect_from_security_hub(
            "2.5.3", ["iam-user-mfa-enabled", "root-account-mfa-enabled"]
        )
        self.assertEqual(results, [])
        self.assertEqual(len(remaining), 2)

    def test_collect_passes_boto3_check_ids(self):
        """boto3_check_ids가 _collect_from_boto3에 전달되는지 확인."""
        s = MagicMock()
        checker = AWSChecker(s)
        checker._sh_enabled = False
        checker._sh_cache = {}

        called_ids = []
        original = checker._collect_from_boto3
        def mock_boto3(isms_p_id, check_ids):
            called_ids.extend(check_ids)
            return []
        checker._collect_from_boto3 = mock_boto3

        checker.collect(
            isms_p_id="2.10.9",
            aws_config_rules=[],
            security_hub_controls=[],
            boto3_check_ids=["guardduty_ec2_malware_protection_enabled"],
        )
        self.assertIn("guardduty_ec2_malware_protection_enabled", called_ids)


# ── Evaluator ─────────────────────────────────────────────────────────────────

class TestEvaluatorAggregate(unittest.TestCase):

    def _cr(self, status):
        return CheckResult("2.5.3", "some-rule", status, "config_rule")

    def test_all_compliant(self):
        self.assertEqual(
            Evaluator._aggregate([self._cr(ComplianceStatus.COMPLIANT)] * 3),
            ComplianceStatus.COMPLIANT
        )

    def test_one_non_compliant(self):
        results = [self._cr(ComplianceStatus.COMPLIANT), self._cr(ComplianceStatus.NON_COMPLIANT)]
        self.assertEqual(Evaluator._aggregate(results), ComplianceStatus.NON_COMPLIANT)

    def test_empty(self):
        self.assertEqual(Evaluator._aggregate([]), ComplianceStatus.INSUFFICIENT_DATA)

    def test_primary_source_priority(self):
        results = [
            CheckResult("2.5.3", "r1", ComplianceStatus.COMPLIANT, "config_rule"),
            CheckResult("2.5.3", "r2", ComplianceStatus.COMPLIANT, "security_hub"),
        ]
        self.assertEqual(Evaluator._primary_source(results), "security_hub")

    def test_extract_reason_non_compliant(self):
        cr = CheckResult("2.5.3", "iam-mfa", ComplianceStatus.NON_COMPLIANT, "config_rule", reason="MFA 미설정")
        reason = Evaluator._extract_reason([cr], ComplianceStatus.NON_COMPLIANT)
        self.assertIn("MFA 미설정", reason)

    def test_extract_reason_compliant_is_none(self):
        cr = CheckResult("2.5.3", "iam-mfa", ComplianceStatus.COMPLIANT, "config_rule")
        self.assertIsNone(Evaluator._extract_reason([cr], ComplianceStatus.COMPLIANT))


class TestEvaluatorOutputStructure(unittest.TestCase):
    """run() 출력이 대시보드 연동 구조를 갖추는지 확인."""

    BASE = Path(__file__).parent.parent / "mappings"

    def setUp(self):
        if not (self.BASE / "isms_p_automatable.json").exists():
            self.skipTest("매핑 파일 없음")
        s = MagicMock()
        checker = AWSChecker(s)
        checker._sh_enabled = False
        checker._sh_cache = {}
        checker._collect_from_boto3 = lambda *a, **kw: []
        checker._collect_from_config = lambda *a, **kw: ([], [])
        checker._collect_from_security_hub = lambda *a, **kw: ([], [])
        self.evaluator = Evaluator(checker)
        self.evaluator.load_mappings()

    def test_run_returns_items_not_split(self):
        """automated_results/manual_items 분리 아닌 items 단일 배열."""
        report = self.evaluator.run()
        self.assertIn("items", report)
        self.assertNotIn("automated_results", report)
        self.assertNotIn("manual_items", report)

    def test_items_count_101(self):
        report = self.evaluator.run()
        self.assertEqual(len(report["items"]), 101)

    def test_each_item_has_required_fields(self):
        report = self.evaluator.run()
        required = {"isms_p_id", "isms_p_name", "domain", "subdomain",
                    "status", "automation_level", "source", "reason",
                    "manual_supplement", "checked_at", "check_details"}
        for item in report["items"]:
            missing = required - item.keys()
            self.assertEqual(missing, set(), f"{item['isms_p_id']} 누락 필드: {missing}")

    def test_manual_items_have_manual_required_status(self):
        report = self.evaluator.run()
        manual = [i for i in report["items"] if i["automation_level"] == "manual"]
        self.assertEqual(len(manual), 74)
        for item in manual:
            self.assertEqual(item["status"], "MANUAL_REQUIRED")

    def test_summary_has_required_fields(self):
        report = self.evaluator.run()
        s = report["summary"]
        for key in ("total", "compliant", "non_compliant", "insufficient_data",
                    "manual_required", "compliance_rate_pct"):
            self.assertIn(key, s)
        self.assertEqual(s["total"], 101)
        self.assertEqual(s["manual_required"], 74)

    def test_boto3_only_items_attempted(self):
        """boto3 전용 7개 항목이 _BOTO3_ONLY_CHECKS에 모두 있는지."""
        auto_ids = {r["isms_p_id"] for r in self.evaluator._automatable}
        for isms_id in _BOTO3_ONLY_CHECKS:
            self.assertIn(isms_id, auto_ids, f"{isms_id}이 automatable에 없음")


# ── 매핑 파일 검증 ─────────────────────────────────────────────────────────────

class TestMappingFiles(unittest.TestCase):
    BASE = Path(__file__).parent.parent / "mappings"

    def _load(self, fname):
        path = self.BASE / fname
        if not path.exists(): self.skipTest(f"{fname} 없음")
        with open(path) as f: return json.load(f)

    def test_full_101(self):
        self.assertEqual(len(self._load("isms_p_full_mapping.json")["requirements"]), 101)

    def test_automatable_27(self):
        d = self._load("isms_p_automatable.json")
        self.assertEqual(len(d["requirements"]), 27)
        for r in d["requirements"]:
            self.assertIn(r["automation_level"], ("full", "partial"))
            self.assertIn("domain", r)
            self.assertIn("subdomain", r)

    def test_manual_74(self):
        self.assertEqual(len(self._load("isms_p_manual.json")["requirements"]), 74)

    def test_no_overlap(self):
        auto   = {r["isms_p_id"] for r in self._load("isms_p_automatable.json")["requirements"]}
        manual = {r["isms_p_id"] for r in self._load("isms_p_manual.json")["requirements"]}
        self.assertEqual(auto & manual, set())
        self.assertEqual(len(auto) + len(manual), 101)


if __name__ == "__main__":
    unittest.main(verbosity=2)
