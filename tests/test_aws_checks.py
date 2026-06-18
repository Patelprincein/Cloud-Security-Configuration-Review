"""
Tests for modules/aws_checks.py

All subprocess calls are mocked so tests run without an AWS CLI or live account.
"""

import json
import base64
import csv
import io
import unittest
from unittest.mock import patch, MagicMock

from modules.aws_checks import (
    check_aws_root_account_mfa,
    check_aws_iam_mfa,
    check_aws_s3_public_access,
    check_aws_cloudtrail_enabled,
    check_aws_security_groups_unrestricted_ssh_rdp,
    run_all_aws_checks,
)


def _mock_run(stdout_data, returncode=0):
    """Return a MagicMock that looks like a successful subprocess.run result."""
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = json.dumps(stdout_data) if stdout_data is not None else ""
    mock.stderr = ""
    return mock


def _csv_credential_report(rows):
    """Build a base64-encoded CSV credential report for testing check_aws_iam_mfa."""
    fieldnames = ["user", "password_enabled", "mfa_active"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    encoded = base64.b64encode(buf.getvalue().encode()).decode()
    return {"Content": encoded}


# ---------------------------------------------------------------------------
# Root Account MFA
# ---------------------------------------------------------------------------

class TestCheckAwsRootAccountMfa(unittest.TestCase):

    @patch("modules.aws_checks.subprocess.run")
    def test_mfa_not_enabled_returns_critical_finding(self, mock_run):
        mock_run.return_value = _mock_run({"SummaryMap": {"AccountMFAEnabled": 0}})
        findings = check_aws_root_account_mfa()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Critical")
        self.assertIn("root", findings[0]["Finding"].lower())

    @patch("modules.aws_checks.subprocess.run")
    def test_mfa_enabled_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run({"SummaryMap": {"AccountMFAEnabled": 1}})
        findings = check_aws_root_account_mfa()
        self.assertEqual(len(findings), 0)

    @patch("modules.aws_checks.subprocess.run")
    def test_cli_failure_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        findings = check_aws_root_account_mfa()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# IAM MFA
# ---------------------------------------------------------------------------

class TestCheckAwsIamMfa(unittest.TestCase):

    @patch("modules.aws_checks.subprocess.run")
    def test_user_without_mfa_returns_finding(self, mock_run):
        report = _csv_credential_report([
            {"user": "alice", "password_enabled": "true", "mfa_active": "false"},
        ])
        # Call 1 = generate-credential-report (ignored output), Call 2 = get-credential-report
        mock_run.side_effect = [
            _mock_run({"State": "COMPLETE"}),
            _mock_run(report),
        ]
        findings = check_aws_iam_mfa()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Resource ID / Name"], "alice")
        self.assertEqual(findings[0]["Severity"], "High")

    @patch("modules.aws_checks.subprocess.run")
    def test_user_with_mfa_returns_no_finding(self, mock_run):
        report = _csv_credential_report([
            {"user": "bob", "password_enabled": "true", "mfa_active": "true"},
        ])
        mock_run.side_effect = [
            _mock_run({"State": "COMPLETE"}),
            _mock_run(report),
        ]
        findings = check_aws_iam_mfa()
        self.assertEqual(len(findings), 0)

    @patch("modules.aws_checks.subprocess.run")
    def test_service_account_no_password_not_flagged(self, mock_run):
        report = _csv_credential_report([
            {"user": "svc-bot", "password_enabled": "false", "mfa_active": "false"},
        ])
        mock_run.side_effect = [
            _mock_run({"State": "COMPLETE"}),
            _mock_run(report),
        ]
        findings = check_aws_iam_mfa()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# S3 Public Access
# ---------------------------------------------------------------------------

class TestCheckAwsS3PublicAccess(unittest.TestCase):

    @patch("modules.aws_checks.subprocess.run")
    def test_bucket_with_no_block_config_is_critical(self, mock_run):
        # First call: list-buckets; subsequent calls: get-public-access-block → fail
        mock_run.side_effect = [
            _mock_run({"Buckets": [{"Name": "my-public-bucket"}]}),
            _mock_run(None, returncode=1),  # no block config exists
        ]
        findings = check_aws_s3_public_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Critical")

    @patch("modules.aws_checks.subprocess.run")
    def test_bucket_partially_blocked_is_high(self, mock_run):
        block_config = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,   # disabled
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_run.side_effect = [
            _mock_run({"Buckets": [{"Name": "partial-bucket"}]}),
            _mock_run(block_config),
        ]
        findings = check_aws_s3_public_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")

    @patch("modules.aws_checks.subprocess.run")
    def test_fully_blocked_bucket_returns_no_finding(self, mock_run):
        block_config = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_run.side_effect = [
            _mock_run({"Buckets": [{"Name": "secure-bucket"}]}),
            _mock_run(block_config),
        ]
        findings = check_aws_s3_public_access()
        self.assertEqual(len(findings), 0)

    @patch("modules.aws_checks.subprocess.run")
    def test_no_buckets_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run({"Buckets": []})
        findings = check_aws_s3_public_access()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

class TestCheckAwsCloudTrailEnabled(unittest.TestCase):

    @patch("modules.aws_checks.subprocess.run")
    def test_no_trails_returns_critical_finding(self, mock_run):
        mock_run.return_value = _mock_run({"trailList": []})
        findings = check_aws_cloudtrail_enabled()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Critical")

    @patch("modules.aws_checks.subprocess.run")
    def test_single_region_trail_returns_high_finding(self, mock_run):
        mock_run.return_value = _mock_run(
            {"trailList": [{"Name": "my-trail", "IsMultiRegionTrail": False}]}
        )
        findings = check_aws_cloudtrail_enabled()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")

    @patch("modules.aws_checks.subprocess.run")
    def test_multi_region_trail_returns_no_finding(self, mock_run):
        mock_run.return_value = _mock_run(
            {"trailList": [{"Name": "global-trail", "IsMultiRegionTrail": True}]}
        )
        findings = check_aws_cloudtrail_enabled()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------

class TestCheckAwsSecurityGroupsSshRdp(unittest.TestCase):

    def _make_sg(self, sg_id, port, cidr_ipv4=None, cidr_ipv6=None):
        ip_ranges = [{"CidrIp": cidr_ipv4}] if cidr_ipv4 else []
        ipv6_ranges = [{"CidrIpv6": cidr_ipv6}] if cidr_ipv6 else []
        return {
            "GroupId": sg_id,
            "GroupName": f"sg-{port}",
            "IpPermissions": [
                {
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": ip_ranges,
                    "Ipv6Ranges": ipv6_ranges,
                }
            ],
        }

    @patch("modules.aws_checks.subprocess.run")
    def test_open_ssh_ipv4_returns_critical(self, mock_run):
        sg = self._make_sg("sg-001", 22, cidr_ipv4="0.0.0.0/0")
        mock_run.return_value = _mock_run({"SecurityGroups": [sg]})
        findings = check_aws_security_groups_unrestricted_ssh_rdp()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Critical")
        self.assertIn("SSH", findings[0]["Finding"])

    @patch("modules.aws_checks.subprocess.run")
    def test_open_rdp_ipv6_returns_critical(self, mock_run):
        sg = self._make_sg("sg-002", 3389, cidr_ipv6="::/0")
        mock_run.return_value = _mock_run({"SecurityGroups": [sg]})
        findings = check_aws_security_groups_unrestricted_ssh_rdp()
        self.assertEqual(len(findings), 1)
        self.assertIn("RDP", findings[0]["Finding"])

    @patch("modules.aws_checks.subprocess.run")
    def test_restricted_sg_returns_no_finding(self, mock_run):
        sg = self._make_sg("sg-003", 22, cidr_ipv4="10.0.0.0/8")
        mock_run.return_value = _mock_run({"SecurityGroups": [sg]})
        findings = check_aws_security_groups_unrestricted_ssh_rdp()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class TestRunAllAwsChecks(unittest.TestCase):

    @patch("modules.aws_checks.subprocess.run")
    def test_returns_list(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        result = run_all_aws_checks()
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
