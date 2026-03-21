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
from unittest.mock import MagicMock, patch

# botocore mock (설치 없이도 import 가능하게)
if "botocore" not in sys.modules:
    bc = MagicMock()
    bc.exceptions.ClientError = Exception
    sys.modules["botocore"] = bc
    sys.modules["botocore.exceptions"] = bc.exceptions

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ismsp.checker.aws_checker import AWSChecker, ComplianceStatus, CheckResult
from ismsp.checker.evaluator   import Evaluator, ItemResult


def _session(iam_mfa=1, iam_keys=0):
    """기본 Mock 세션 생성."""
    s = MagicMock()
    iam = MagicMock()
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountMFAEnabled": iam_mfa, "AccountAccessKeysPresent": iam_keys}
    }
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:test"}
    s.client.side_effect = lambda svc, **kw: {"iam": iam, "sts": sts}.get(svc, MagicMock())
    return s


# ── AWSChecker 테스트 ──────────────────────────────────────────────────────────

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
        self.assertIn("액세스 키", reason)

    def test_backup_plans_exist(self):
        s = MagicMock()
        backup = MagicMock()
        backup.list_backup_plans.return_value = {"BackupPlansList": [{"id": "p1"}]}
        backup.list_backup_vaults.return_value = {"BackupVaultList": [{"name": "Default"}]}
        s.client.return_value = backup
        checker = AWSChecker(s)
        status, _ = checker._check_backup_plans()
        self.assertEqual(status, ComplianceStatus.COMPLIANT)

    def test_backup_plans_missing(self):
        s = MagicMock()
        backup = MagicMock()
        backup.list_backup_plans.return_value = {"BackupPlansList": []}
        backup.list_backup_vaults.return_value = {"BackupVaultList": []}
        s.client.return_value = backup
        checker = AWSChecker(s)
        status, reason = checker._check_backup_plans()
        self.assertEqual(status, ComplianceStatus.NON_COMPLIANT)
        self.assertIn("Backup 플랜", reason)

    def test_sh_disabled_falls_back(self):
        """Security Hub 비활성화 시 remaining에 모두 반환."""
        from unittest.mock import patch
        s = MagicMock()
        checker = AWSChecker(s)
        checker._sh_enabled = False          # SH 비활성으로 강제 설정
        results, remaining = checker._collect_from_security_hub(
            "2.5.3", ["iam-user-mfa-enabled", "root-account-mfa-enabled"]
        )
        self.assertEqual(results, [])
        self.assertEqual(len(remaining), 2)


# ── Evaluator 테스트 ───────────────────────────────────────────────────────────

class TestEvaluatorAggregate(unittest.TestCase):

    def _make_result(self, status: ComplianceStatus) -> CheckResult:
        return CheckResult("2.5.3", "some-rule", status, "config_rule")

    def test_all_compliant(self):
        results = [self._make_result(ComplianceStatus.COMPLIANT)] * 3
        self.assertEqual(Evaluator._aggregate(results), ComplianceStatus.COMPLIANT)

    def test_one_non_compliant(self):
        results = [
            self._make_result(ComplianceStatus.COMPLIANT),
            self._make_result(ComplianceStatus.NON_COMPLIANT),
        ]
        self.assertEqual(Evaluator._aggregate(results), ComplianceStatus.NON_COMPLIANT)

    def test_empty_results(self):
        self.assertEqual(Evaluator._aggregate([]), ComplianceStatus.INSUFFICIENT_DATA)

    def test_primary_source_priority(self):
        results = [
            CheckResult("2.5.3", "r1", ComplianceStatus.COMPLIANT, "config_rule"),
            CheckResult("2.5.3", "r2", ComplianceStatus.COMPLIANT, "security_hub"),
        ]
        self.assertEqual(Evaluator._primary_source(results), "security_hub")


# ── 매핑 JSON 구조 검증 ────────────────────────────────────────────────────────

class TestMappingFiles(unittest.TestCase):

    BASE = Path(__file__).parent.parent / "mappings"

    def _load(self, fname):
        path = self.BASE / fname
        if not path.exists():
            self.skipTest(f"{fname} 없음")
        with open(path) as f:
            return json.load(f)

    def test_full_mapping_101(self):
        d = self._load("isms_p_full_mapping.json")
        self.assertEqual(len(d["requirements"]), 101)

    def test_automatable_27(self):
        d = self._load("isms_p_automatable.json")
        self.assertEqual(len(d["requirements"]), 27)
        for r in d["requirements"]:
            self.assertTrue(r["automatable"])
            self.assertIn(r["automation_level"], ("full", "partial"))

    def test_manual_74(self):
        d = self._load("isms_p_manual.json")
        self.assertEqual(len(d["requirements"]), 74)
        for r in d["requirements"]:
            self.assertFalse(r["automatable"])

    def test_no_overlap(self):
        auto   = {r["isms_p_id"] for r in self._load("isms_p_automatable.json")["requirements"]}
        manual = {r["isms_p_id"] for r in self._load("isms_p_manual.json")["requirements"]}
        self.assertEqual(auto & manual, set(), "자동화/수동 항목 ID 중복 있음")
        self.assertEqual(len(auto) + len(manual), 101)


if __name__ == "__main__":
    unittest.main(verbosity=2)
