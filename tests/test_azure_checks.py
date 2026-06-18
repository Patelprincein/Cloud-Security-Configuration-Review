"""
Tests for modules/azure_checks.py

All subprocess calls are mocked so tests run without an Azure CLI or live account.
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from modules.azure_checks import (
    check_azure_mfa_conditional_access,
    check_azure_iam_guest_users,
    check_azure_storage_secure_transfer,
    check_azure_nsg_unrestricted_access,
    run_all_azure_checks,
)


def _mock_run(stdout_data, returncode=0):
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = json.dumps(stdout_data) if stdout_data is not None else ""
    mock.stderr = ""
    return mock


# ---------------------------------------------------------------------------
# MFA / Conditional Access
# ---------------------------------------------------------------------------

class TestCheckAzureMfaConditionalAccess(unittest.TestCase):

    @patch("modules.azure_checks.subprocess.run")
    def test_cli_failure_returns_medium_finding(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        findings = check_azure_mfa_conditional_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Medium")

    @patch("modules.azure_checks.subprocess.run")
    def test_no_mfa_policy_returns_high_finding(self, mock_run):
        mock_run.return_value = _mock_run({
            "value": [
                {
                    "state": "enabled",
                    "grantControls": {"builtInControls": ["block"]},
                }
            ]
        })
        findings = check_azure_mfa_conditional_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")

    @patch("modules.azure_checks.subprocess.run")
    def test_mfa_policy_present_returns_no_finding(self, mock_run):
        mock_run.return_value = _mock_run({
            "value": [
                {
                    "state": "enabled",
                    "grantControls": {"builtInControls": ["mfa"]},
                }
            ]
        })
        findings = check_azure_mfa_conditional_access()
        self.assertEqual(len(findings), 0)

    @patch("modules.azure_checks.subprocess.run")
    def test_empty_policy_list_returns_high_finding(self, mock_run):
        mock_run.return_value = _mock_run({"value": []})
        findings = check_azure_mfa_conditional_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")


# ---------------------------------------------------------------------------
# Guest Users
# ---------------------------------------------------------------------------

class TestCheckAzureIamGuestUsers(unittest.TestCase):

    @patch("modules.azure_checks.subprocess.run")
    def test_guest_user_returns_medium_finding(self, mock_run):
        mock_run.return_value = _mock_run([
            {"userPrincipalName": "external_user#EXT#@tenant.onmicrosoft.com",
             "displayName": "External User"}
        ])
        findings = check_azure_iam_guest_users()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Medium")

    @patch("modules.azure_checks.subprocess.run")
    def test_no_guest_users_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run([])
        findings = check_azure_iam_guest_users()
        self.assertEqual(len(findings), 0)

    @patch("modules.azure_checks.subprocess.run")
    def test_cli_failure_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        findings = check_azure_iam_guest_users()
        self.assertEqual(len(findings), 0)

    @patch("modules.azure_checks.subprocess.run")
    def test_multiple_guests_return_multiple_findings(self, mock_run):
        mock_run.return_value = _mock_run([
            {"userPrincipalName": "guest1#EXT#@tenant.com", "displayName": "Guest 1"},
            {"userPrincipalName": "guest2#EXT#@tenant.com", "displayName": "Guest 2"},
        ])
        findings = check_azure_iam_guest_users()
        self.assertEqual(len(findings), 2)


# ---------------------------------------------------------------------------
# Storage Secure Transfer
# ---------------------------------------------------------------------------

class TestCheckAzureStorageSecureTransfer(unittest.TestCase):

    @patch("modules.azure_checks.subprocess.run")
    def test_http_allowed_returns_high_finding(self, mock_run):
        mock_run.return_value = _mock_run([
            {"name": "mystorage", "enableHttpsTrafficOnly": False}
        ])
        findings = check_azure_storage_secure_transfer()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "High")
        self.assertEqual(findings[0]["Resource ID / Name"], "mystorage")

    @patch("modules.azure_checks.subprocess.run")
    def test_https_enforced_returns_no_finding(self, mock_run):
        mock_run.return_value = _mock_run([
            {"name": "securestorage", "enableHttpsTrafficOnly": True}
        ])
        findings = check_azure_storage_secure_transfer()
        self.assertEqual(len(findings), 0)

    @patch("modules.azure_checks.subprocess.run")
    def test_no_accounts_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run([])
        findings = check_azure_storage_secure_transfer()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# NSG Unrestricted Access
# ---------------------------------------------------------------------------

class TestCheckAzureNsgUnrestrictedAccess(unittest.TestCase):

    def _make_nsg(self, name, rg, port, source):
        return {
            "name": name,
            "resourceGroup": rg,
            "securityRules": [
                {
                    "name": "allow-rule",
                    "direction": "Inbound",
                    "access": "Allow",
                    "destinationPortRange": str(port),
                    "sourceAddressPrefix": source,
                }
            ],
        }

    @patch("modules.azure_checks.subprocess.run")
    def test_open_ssh_nsg_returns_critical(self, mock_run):
        nsg = self._make_nsg("nsg-ssh", "rg-prod", 22, "*")
        mock_run.return_value = _mock_run([nsg])
        findings = check_azure_nsg_unrestricted_access()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["Severity"], "Critical")
        self.assertIn("SSH", findings[0]["Finding"])

    @patch("modules.azure_checks.subprocess.run")
    def test_open_rdp_nsg_returns_critical(self, mock_run):
        nsg = self._make_nsg("nsg-rdp", "rg-prod", 3389, "Internet")
        mock_run.return_value = _mock_run([nsg])
        findings = check_azure_nsg_unrestricted_access()
        self.assertEqual(len(findings), 1)
        self.assertIn("RDP", findings[0]["Finding"])

    @patch("modules.azure_checks.subprocess.run")
    def test_restricted_nsg_returns_no_finding(self, mock_run):
        nsg = self._make_nsg("nsg-ok", "rg-prod", 22, "10.0.0.0/8")
        mock_run.return_value = _mock_run([nsg])
        findings = check_azure_nsg_unrestricted_access()
        self.assertEqual(len(findings), 0)

    @patch("modules.azure_checks.subprocess.run")
    def test_no_nsgs_returns_no_findings(self, mock_run):
        mock_run.return_value = _mock_run([])
        findings = check_azure_nsg_unrestricted_access()
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class TestRunAllAzureChecks(unittest.TestCase):

    @patch("modules.azure_checks.subprocess.run")
    def test_returns_list(self, mock_run):
        mock_run.return_value = _mock_run(None, returncode=1)
        result = run_all_azure_checks()
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
