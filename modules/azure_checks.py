"""
azure_checks.py
---------------
CIS Benchmark security checks for Microsoft Azure.

All checks use the Azure CLI via subprocess and return a list of finding dicts
conforming to the shared Risk Register schema.

CIS Controls covered:
    1.1  — MFA / Conditional Access for all users
    1.14 — Guest user review
    3.1  — Storage Account secure transfer (HTTPS only)
    6.1  — NSG: unrestricted SSH (port 22)
    6.2  — NSG: unrestricted RDP (port 3389)
"""

import subprocess
import json


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def run_az_command(command):
    """Run an Azure CLI command and return the parsed JSON output, or None on failure."""
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
        )
        if result.returncode != 0:
            # Uncomment the line below to debug CLI errors:
            # print(f"    [debug] {result.stderr.strip()}")
            return None
        stdout = result.stdout.strip()
        if not stdout:
            return None
        return json.loads(stdout)
    except json.JSONDecodeError:
        print(f"[-] Azure CLI returned non-JSON output for: {command}")
        return None
    except Exception as e:
        print(f"[-] Error executing command: {e}")
        return None


# ---------------------------------------------------------------------------
# CIS Azure 1.1 — MFA / Conditional Access
# ---------------------------------------------------------------------------

def check_azure_mfa_conditional_access():
    """
    CIS Azure 1.1: Ensure that multi-factor authentication is enabled for all
    privileged users (via Conditional Access).

    Note: This check queries Conditional Access policies via Microsoft Graph.
    It flags environments where NO policy requiring MFA exists.
    """
    findings = []
    print("[*] Azure: Checking for MFA / Conditional Access policies (CIS 1.1)...")

    policies = run_az_command(
        "az rest --method GET "
        "--url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies "
        "--output json"
    )

    if not policies:
        # CLI may not have Graph permissions — flag as informational rather than error
        findings.append({
            "Cloud Provider": "Azure",
            "Resource ID / Name": "Entra ID Tenant",
            "Finding": (
                "Unable to retrieve Conditional Access policies. This may indicate "
                "insufficient permissions OR that no policies have been configured. "
                "Verify MFA enforcement manually in the Azure Portal."
            ),
            "Severity": "Medium",
            "CIS Benchmark": "CIS Azure 1.1",
            "Mitigation Strategy": (
                "Navigate to: Azure Portal → Microsoft Entra ID → Security → "
                "Conditional Access → Policies and create a policy requiring MFA "
                "for all users accessing cloud applications."
            ),
            "Status": "Open",
        })
        return findings

    policy_list = policies.get("value", [])
    # Look for any enabled policy that grants with MFA requirement
    mfa_policies = [
        p for p in policy_list
        if p.get("state") == "enabled"
        and "mfa" in str(p.get("grantControls", "")).lower()
    ]

    if not mfa_policies:
        findings.append({
            "Cloud Provider": "Azure",
            "Resource ID / Name": "Entra ID Tenant",
            "Finding": (
                "No enabled Conditional Access policy requiring MFA was found. "
                "Users may be able to authenticate with only a password."
            ),
            "Severity": "High",
            "CIS Benchmark": "CIS Azure 1.1",
            "Mitigation Strategy": (
                "Create a Conditional Access policy: Azure Portal → Microsoft Entra ID "
                "→ Security → Conditional Access → New Policy. "
                "Set 'Grant access' with 'Require multifactor authentication'."
            ),
            "Status": "Open",
        })

    return findings


# ---------------------------------------------------------------------------
# CIS Azure 1.14 — Guest Users
# ---------------------------------------------------------------------------

def check_azure_iam_guest_users():
    """
    CIS Azure 1.14: Ensure that 'Guest' users are reviewed periodically.

    Guest accounts (external collaborators) with stale or excessive access
    can be a vector for unauthorized data exfiltration.
    """
    findings = []
    print("[*] Azure: Checking for Guest user accounts in Entra ID (CIS 1.14)...")

    users = run_az_command(
        "az ad user list --filter \"userType eq 'Guest'\" --output json"
    )

    if not users:
        return findings

    for user in users:
        name = user.get("userPrincipalName", "Unknown")
        display_name = user.get("displayName", "Unknown")
        findings.append({
            "Cloud Provider": "Azure",
            "Resource ID / Name": f"{display_name} ({name})",
            "Finding": (
                "Guest user account detected in Entra ID. "
                "External accounts require periodic access review to prevent unauthorized access."
            ),
            "Severity": "Medium",
            "CIS Benchmark": "CIS Azure 1.14",
            "Mitigation Strategy": (
                "Review account necessity via Azure Portal → Microsoft Entra ID → Users. "
                "Remove the guest account if inactive or no longer required: "
                f"az ad user delete --id {name}"
            ),
            "Status": "Open",
        })

    return findings


# ---------------------------------------------------------------------------
# CIS Azure 3.1 — Storage Account Secure Transfer
# ---------------------------------------------------------------------------

def check_azure_storage_secure_transfer():
    """
    CIS Azure 3.1: Ensure that 'Secure transfer required' is set to 'Enabled'.

    If HTTPS is not enforced, data in transit to/from the storage account
    can be intercepted via a man-in-the-middle attack.
    """
    findings = []
    print("[*] Azure: Checking Storage Accounts for HTTPS enforcement (CIS 3.1)...")

    accounts = run_az_command("az storage account list --output json")
    if not accounts:
        return findings

    for account in accounts:
        name = account.get("name", "Unknown")
        secure_transfer = account.get("enableHttpsTrafficOnly", False)

        if not secure_transfer:
            findings.append({
                "Cloud Provider": "Azure",
                "Resource ID / Name": name,
                "Finding": (
                    f"Storage Account '{name}' does not enforce HTTPS. "
                    "HTTP traffic is permitted, risking data interception in transit."
                ),
                "Severity": "High",
                "CIS Benchmark": "CIS Azure 3.1",
                "Mitigation Strategy": (
                    f"Enforce HTTPS: az storage account update --name {name} --https-only true"
                ),
                "Status": "Open",
            })

    return findings


# ---------------------------------------------------------------------------
# CIS Azure 6.1 / 6.2 — NSG Unrestricted SSH / RDP
# ---------------------------------------------------------------------------

def check_azure_nsg_unrestricted_access():
    """
    CIS Azure 6.1 / 6.2: Ensure that Network Security Groups do not allow
    unrestricted inbound access on SSH (port 22) or RDP (port 3389).

    Unrestricted management port access exposes VMs to brute-force attacks.
    """
    findings = []
    print("[*] Azure: Checking NSGs for unrestricted SSH/RDP ingress (CIS 6.1/6.2)...")

    nsgs = run_az_command("az network nsg list --output json")
    if not nsgs:
        return findings

    risky_ports = {
        "22": ("SSH", "CIS Azure 6.1"),
        "3389": ("RDP", "CIS Azure 6.2"),
    }
    open_sources = {"*", "Internet", "0.0.0.0/0", "::/0", "0.0.0.0"}

    for nsg in nsgs:
        nsg_name = nsg.get("name", "Unknown")
        rg = nsg.get("resourceGroup", "Unknown")
        resource_label = f"{nsg_name} (RG: {rg})"

        for rule in nsg.get("securityRules", []):
            direction = rule.get("direction", "")
            access = rule.get("access", "")
            if direction != "Inbound" or access != "Allow":
                continue

            dest_port = rule.get("destinationPortRange", "")
            source_addr = rule.get("sourceAddressPrefix", "")

            for port, (service, cis_ref) in risky_ports.items():
                if dest_port in (port, "*") and source_addr in open_sources:
                    findings.append({
                        "Cloud Provider": "Azure",
                        "Resource ID / Name": resource_label,
                        "Finding": (
                            f"NSG '{nsg_name}' allows unrestricted inbound {service} (port {port}) "
                            f"from source '{source_addr}'. Any host on the internet can connect."
                        ),
                        "Severity": "Critical",
                        "CIS Benchmark": cis_ref,
                        "Mitigation Strategy": (
                            f"Restrict access to trusted IP ranges: "
                            f"az network nsg rule update --resource-group {rg} "
                            f"--nsg-name {nsg_name} --name {rule.get('name', '<rule>')} "
                            f"--source-address-prefixes <trusted-ip-range>"
                        ),
                        "Status": "Open",
                    })

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_azure_checks():
    """Execute all Azure CIS checks and return a consolidated list of findings."""
    all_findings = []
    all_findings.extend(check_azure_mfa_conditional_access())
    all_findings.extend(check_azure_storage_secure_transfer())
    all_findings.extend(check_azure_iam_guest_users())
    all_findings.extend(check_azure_nsg_unrestricted_access())
    return all_findings
