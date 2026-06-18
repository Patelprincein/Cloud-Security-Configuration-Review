"""
aws_checks.py
-------------
CIS Benchmark security checks for Amazon Web Services (AWS).

All checks use the AWS CLI via subprocess and return a list of finding dicts
conforming to the shared Risk Register schema.

CIS Controls covered:
    1.5  — Root account MFA
    1.10 — IAM user MFA for console users
    2.1  — S3 bucket public access block
    3.1  — CloudTrail enabled in all regions
    5.2  — Security Groups: unrestricted SSH (port 22)
    5.3  — Security Groups: unrestricted RDP (port 3389)
"""

import subprocess
import json
import base64
import csv
import io


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def run_aws_command(command):
    """Run an AWS CLI command and return the parsed JSON output, or None on failure."""
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
        print(f"[-] AWS CLI returned non-JSON output for: {command}")
        return None
    except Exception as e:
        print(f"[-] Error executing command: {e}")
        return None


# ---------------------------------------------------------------------------
# CIS AWS 1.5 — Root Account MFA
# ---------------------------------------------------------------------------

def check_aws_root_account_mfa():
    """
    CIS AWS 1.5: Ensure MFA is enabled for the root account.

    The root account has unrestricted access to all AWS resources. If MFA is
    not enabled it becomes a single point of catastrophic failure.
    """
    findings = []
    print("[*] AWS: Checking Root Account MFA status (CIS 1.5)...")

    data = run_aws_command("aws iam get-account-summary --output json")
    if not data:
        return findings

    summary_map = data.get("SummaryMap", {})
    mfa_enabled = summary_map.get("AccountMFAEnabled", 0)

    if mfa_enabled != 1:
        findings.append({
            "Cloud Provider": "AWS",
            "Resource ID / Name": "Root Account",
            "Finding": (
                "MFA is NOT enabled on the AWS root account. "
                "This is a critical risk — the root account has unrestricted access."
            ),
            "Severity": "Critical",
            "CIS Benchmark": "CIS AWS 1.5",
            "Mitigation Strategy": (
                "Enable MFA on the root account via the AWS Console: "
                "IAM → Security credentials → Multi-factor authentication (MFA)."
            ),
            "Status": "Open",
        })

    return findings


# ---------------------------------------------------------------------------
# CIS AWS 1.10 — IAM User MFA
# ---------------------------------------------------------------------------

def check_aws_iam_mfa():
    """
    CIS AWS 1.10: Ensure MFA is enabled for all IAM users that have a console password.

    Identifies IAM misconfigurations where human users can log in without a second factor.
    """
    findings = []
    print("[*] AWS: Checking IAM Users for MFA enablement (CIS 1.10)...")

    # Generate credential report (AWS may take a few seconds to produce it)
    run_aws_command("aws iam generate-credential-report --output json")

    report_data = run_aws_command("aws iam get-credential-report --output json")
    if not report_data:
        return findings

    content = report_data.get("Content", "")
    try:
        decoded = base64.b64decode(content).decode("utf-8")
    except Exception:
        return findings

    reader = csv.DictReader(io.StringIO(decoded))
    for row in reader:
        username = row.get("user", "Unknown")
        password_enabled = row.get("password_enabled", "false").lower()
        mfa_active = row.get("mfa_active", "false").lower()

        # Only flag human users with a console password who lack MFA
        if password_enabled == "true" and mfa_active == "false":
            findings.append({
                "Cloud Provider": "AWS",
                "Resource ID / Name": username,
                "Finding": (
                    "IAM user has a console password but MFA is NOT enabled. "
                    "High risk of account takeover via credential stuffing."
                ),
                "Severity": "High",
                "CIS Benchmark": "CIS AWS 1.10",
                "Mitigation Strategy": (
                    f"Enable MFA for '{username}' via the IAM console or use: "
                    f"aws iam enable-mfa-device --user-name {username} "
                    f"--serial-number <MFA_ARN> --authentication-code1 <code1> "
                    f"--authentication-code2 <code2>"
                ),
                "Status": "Open",
            })

    return findings


# ---------------------------------------------------------------------------
# CIS AWS 2.1.1 / 2.1.2 — S3 Public Access Block
# ---------------------------------------------------------------------------

def check_aws_s3_public_access():
    """
    CIS AWS 2.1.1 / 2.1.2: Ensure S3 buckets block all forms of public access.

    Misconfigured S3 buckets are one of the most common causes of cloud data breaches.
    """
    findings = []
    print("[*] AWS: Checking S3 Buckets for Public Access Block (CIS 2.1)...")

    buckets_data = run_aws_command("aws s3api list-buckets --output json")
    if not buckets_data:
        return findings

    for bucket in buckets_data.get("Buckets", []):
        name = bucket.get("Name", "Unknown")
        block_config = run_aws_command(
            f"aws s3api get-public-access-block --bucket {name} --output json"
        )

        if not block_config:
            # No block config at all — bucket may be fully public
            findings.append({
                "Cloud Provider": "AWS",
                "Resource ID / Name": name,
                "Finding": (
                    "S3 bucket has NO Public Access Block configuration. "
                    "The bucket may be publicly accessible."
                ),
                "Severity": "Critical",
                "CIS Benchmark": "CIS AWS 2.1.1",
                "Mitigation Strategy": (
                    f"Run: aws s3api put-public-access-block --bucket {name} "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                "Status": "Open",
            })
            continue

        config = block_config.get("PublicAccessBlockConfiguration", {})
        all_blocked = (
            config.get("BlockPublicAcls", False)
            and config.get("IgnorePublicAcls", False)
            and config.get("BlockPublicPolicy", False)
            and config.get("RestrictPublicBuckets", False)
        )

        if not all_blocked:
            findings.append({
                "Cloud Provider": "AWS",
                "Resource ID / Name": name,
                "Finding": (
                    "S3 bucket does not fully block public access. "
                    "One or more Public Access Block settings are disabled."
                ),
                "Severity": "High",
                "CIS Benchmark": "CIS AWS 2.1.1",
                "Mitigation Strategy": (
                    f"Run: aws s3api put-public-access-block --bucket {name} "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
                "Status": "Open",
            })

    return findings


# ---------------------------------------------------------------------------
# CIS AWS 3.1 — CloudTrail Multi-Region Logging
# ---------------------------------------------------------------------------

def check_aws_cloudtrail_enabled():
    """
    CIS AWS 3.1: Ensure CloudTrail is enabled in all regions.

    Without CloudTrail, API activity cannot be audited or forensically investigated
    following a security incident.
    """
    findings = []
    print("[*] AWS: Checking CloudTrail multi-region logging (CIS 3.1)...")

    trails_data = run_aws_command("aws cloudtrail describe-trails --include-shadow-trails false --output json")
    if not trails_data:
        return findings

    trails = trails_data.get("trailList", [])

    if not trails:
        findings.append({
            "Cloud Provider": "AWS",
            "Resource ID / Name": "AWS Account",
            "Finding": (
                "No CloudTrail trails found. API activity in this account "
                "is NOT being logged."
            ),
            "Severity": "Critical",
            "CIS Benchmark": "CIS AWS 3.1",
            "Mitigation Strategy": (
                "Create a CloudTrail trail with multi-region logging: "
                "aws cloudtrail create-trail --name <trail-name> "
                "--s3-bucket-name <bucket> --is-multi-region-trail "
                "&& aws cloudtrail start-logging --name <trail-name>"
            ),
            "Status": "Open",
        })
        return findings

    for trail in trails:
        trail_name = trail.get("Name", "Unknown")
        is_multi_region = trail.get("IsMultiRegionTrail", False)

        if not is_multi_region:
            findings.append({
                "Cloud Provider": "AWS",
                "Resource ID / Name": trail_name,
                "Finding": (
                    f"CloudTrail trail '{trail_name}' is NOT configured for multi-region logging. "
                    "API activity in other regions will not be captured."
                ),
                "Severity": "High",
                "CIS Benchmark": "CIS AWS 3.1",
                "Mitigation Strategy": (
                    f"Update the trail: aws cloudtrail update-trail "
                    f"--name {trail_name} --is-multi-region-trail"
                ),
                "Status": "Open",
            })

    return findings


# ---------------------------------------------------------------------------
# CIS AWS 5.2 / 5.3 — Security Groups: Unrestricted SSH / RDP
# ---------------------------------------------------------------------------

def check_aws_security_groups_unrestricted_ssh_rdp():
    """
    CIS AWS 5.2 / 5.3: Ensure no security groups allow unrestricted ingress on
    SSH (port 22) or RDP (port 3389) from the internet.

    Unrestricted access exposes instances to brute-force and exploitation attacks.
    """
    findings = []
    print("[*] AWS: Checking Security Groups for unrestricted SSH/RDP (CIS 5.2/5.3)...")

    sgs_data = run_aws_command("aws ec2 describe-security-groups --output json")
    if not sgs_data:
        return findings

    risky_ports = {22: "SSH", 3389: "RDP"}
    unrestricted_cidrs = {"0.0.0.0/0", "::/0"}

    for sg in sgs_data.get("SecurityGroups", []):
        sg_id = sg.get("GroupId", "Unknown")
        sg_name = sg.get("GroupName", "Unknown")
        resource_label = f"{sg_id} ({sg_name})"

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort", -1)
            to_port = permission.get("ToPort", -1)

            for port, service in risky_ports.items():
                if from_port is None or to_port is None:
                    continue
                if from_port <= port <= to_port:
                    cis_ref = "CIS AWS 5.2" if port == 22 else "CIS AWS 5.3"
                    mitigation = (
                        f"Remove the unrestricted rule and restrict to trusted CIDRs: "
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                        f"--protocol tcp --port {port} --cidr <cidr>"
                    )

                    # Check IPv4
                    for ip_range in permission.get("IpRanges", []):
                        if ip_range.get("CidrIp") in unrestricted_cidrs:
                            findings.append({
                                "Cloud Provider": "AWS",
                                "Resource ID / Name": resource_label,
                                "Finding": (
                                    f"Security Group allows unrestricted {service} (port {port}) "
                                    f"ingress from 0.0.0.0/0 (all IPv4). Any host can attempt a connection."
                                ),
                                "Severity": "Critical",
                                "CIS Benchmark": cis_ref,
                                "Mitigation Strategy": mitigation,
                                "Status": "Open",
                            })

                    # Check IPv6
                    for ip_range in permission.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") in unrestricted_cidrs:
                            findings.append({
                                "Cloud Provider": "AWS",
                                "Resource ID / Name": resource_label,
                                "Finding": (
                                    f"Security Group allows unrestricted {service} (port {port}) "
                                    f"ingress from ::/0 (all IPv6). Any host can attempt a connection."
                                ),
                                "Severity": "Critical",
                                "CIS Benchmark": cis_ref,
                                "Mitigation Strategy": mitigation,
                                "Status": "Open",
                            })

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_aws_checks():
    """Execute all AWS CIS checks and return a consolidated list of findings."""
    all_findings = []
    all_findings.extend(check_aws_root_account_mfa())
    all_findings.extend(check_aws_iam_mfa())
    all_findings.extend(check_aws_s3_public_access())
    all_findings.extend(check_aws_cloudtrail_enabled())
    all_findings.extend(check_aws_security_groups_unrestricted_ssh_rdp())
    return all_findings
