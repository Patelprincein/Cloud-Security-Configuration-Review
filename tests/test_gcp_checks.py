"""
Tests for modules/gcp_checks.py

All subprocess calls are mocked so tests run without a gcloud CLI or live account.
"""

import json
import unittest
from unittest.mock import patch, MagicMock, call

from modules.gcp_checks import (
    check_gcp_iam_service_account_keys,
    check_gcp_audit_logging,
    check_gcp_storage_uniform_access,
    run_all_gcp_checks,
)


def _mock_run(stdout_data, returncode=0):
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = json.dumps(stdout_data) if stdout_data is not None else ""
    mock.stderr = ""
    return mock


MOCK_PROJECT = [{"projectId": "test-project-123"}]
MOCK_SA = [{"email": "my-sa@test-project-123.iam.gserviceaccount.com"}]


# ---------------------------------------------------------------------------
# Service Account Keys
# ---------------------------------------------------------------------------

class TestCheckGcpIamServiceAccountKeys(unittest.TestCase):

    @patch("modules.gcp_checks.subprocess.run")
    def test_user_managed_key_returns_high_finding(self, mock_run):
        key_name = "projects/test-project-123/serviceAccounts/my-sa@test.iam.gserviceaccount.com/keys/abc123def456"
        mock_run.side_effect = [
            _mock_run(MOCK_PROJECT),
            _mock_run(MOCK_SA),
            _mock_run([{"keyType": "USER_MANAGED", "name": key_name}]),
        ]
        findings = check_gcp_iam_service_account_keys()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")
        self.assertIn("USER-MANAGED", findings[0]["Finding"].upper())

    @patch("modules.gcp_checks.subprocess.run")
    def test_gcp_managed_key_returns_no_finding(self, mock_run):
        mock_run.side_effect = [
            _mock_run(MOCK_PROJECT),
            _mock_run(MOCK_SA),
            _mock_run([{"keyType": "SYSTEM_MANAGED", "name": "projects/.../keys/xyz"}]),
        ]
        findings = check_gcp_iam_service_account_keys()
        self.assertEqual(len(findings), 0)

    @patch("modules.gcp_checks.subprocess.run")
    def test_no_projects_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        findings = check_gcp_iam_service_account_keys()
        self.assertEqual(len(findings), 0)

    @patch("modules.gcp_checks.subprocess.run")
    def test_no_service_accounts_returns_no_findings(self, mock_run):
        mock_run.side_effect = [
            _mock_run(MOCK_PROJECT),
            _mock_run([]),
        ]
        findings = check_gcp_iam_service_account_keys()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

class TestCheckGcpAuditLogging(unittest.TestCase):

    @patch("modules.gcp_checks.subprocess.run")
    def test_no_audit_configs_returns_high_finding(self, mock_run):
        mock_run.side_effect = [
            _mock_run(MOCK_PROJECT),
            _mock_run({"bindings": [], "auditConfigs": []}),
        ]
        findings = check_gcp_audit_logging()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")

    @patch("modules.gcp_checks.subprocess.run")
    def test_missing_all_services_returns_medium_finding(self, mock_run):
        mock_run.side_effect = [
            _mock_run(MOCK_PROJECT),
            _mock_run({
                "auditConfigs": [
                    {"service": "storage.googleapis.com", "auditLogConfigs": []}
                ]
            }),
        ]
        findings = check_gcp_audit_logging()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Medium")

    @patch("modules.gcp_checks.subprocess.run")
    def test_all_services_configured_returns_no_finding(self, mock_run):
        mock_run.side_effect = [
            _mock_run(MOCK_PROJECT),
            _mock_run({
                "auditConfigs": [
                    {
                        "service": "allServices",
                        "auditLogConfigs": [
                            {"logType": "ADMIN_READ"},
                            {"logType": "DATA_READ"},
                            {"logType": "DATA_WRITE"},
                        ],
                    }
                ]
            }),
        ]
        findings = check_gcp_audit_logging()
        self.assertEqual(len(findings), 0)

    @patch("modules.gcp_checks.subprocess.run")
    def test_cli_failure_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        findings = check_gcp_audit_logging()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Storage Uniform Bucket-Level Access
# ---------------------------------------------------------------------------

class TestCheckGcpStorageUniformAccess(unittest.TestCase):

    @patch("modules.gcp_checks.subprocess.run")
    def test_uniform_access_disabled_returns_medium_finding(self, mock_run):
        mock_run.return_value = _mock_run([
            {
                "name": "my-bucket",
                "iamConfiguration": {
                    "uniformBucketLevelAccess": {"enabled": False}
                },
            }
        ])
        findings = check_gcp_storage_uniform_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Medium")
        self.assertEqual(findings[0]["Resource ID / Name"], "my-bucket")

    @patch("modules.gcp_checks.subprocess.run")
    def test_uniform_access_enabled_returns_no_finding(self, mock_run):
        mock_run.return_value = _mock_run([
            {
                "name": "secure-bucket",
                "iamConfiguration": {
                    "uniformBucketLevelAccess": {"enabled": True}
                },
            }
        ])
        findings = check_gcp_storage_uniform_access()
        self.assertEqual(len(findings), 0)

    @patch("modules.gcp_checks.subprocess.run")
    def test_no_buckets_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run([])
        findings = check_gcp_storage_uniform_access()
        self.assertEqual(len(findings), 0)

    @patch("modules.gcp_checks.subprocess.run")
    def test_cli_failure_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        findings = check_gcp_storage_uniform_access()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class TestRunAllGcpChecks(unittest.TestCase):

    @patch("modules.gcp_checks.subprocess.run")
    def test_returns_list(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        result = run_all_gcp_checks()
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
