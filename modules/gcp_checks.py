"""
gcp_checks.py
-------------
CIS Benchmark security checks for Google Cloud Platform (GCP).

All checks use the gcloud CLI via subprocess and return a list of finding dicts
conforming to the shared Risk Register schema.

CIS Controls covered:
    1.4  — Service Account user-managed keys
    2.1  — Cloud Audit Logs: admin activity logging enabled
    5.2  — Cloud Storage: Uniform Bucket-Level Access
"""

import subprocess
import json


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def run_gcp_command(command):
    """Run a gcloud CLI command and return the parsed JSON output, or None on failure."""
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
        print(f"[-] GCP CLI returned non-JSON output for: {command}")
        return None
    except Exception as e:
        print(f"[-] Error executing command: {e}")
        return None


def _get_default_project_id():
    """Retrieve the active gcloud project ID."""
    projects = run_gcp_command("gcloud projects list --format=json")
    if not projects:
        return None
    return projects[0].get("projectId")


# ---------------------------------------------------------------------------
# CIS GCP 1.4 — Service Account User-Managed Keys
# ---------------------------------------------------------------------------

def check_gcp_iam_service_account_keys():
    """
    CIS GCP 1.4: Ensure that there are only GCP-managed service account keys.

    User-managed keys are long-lived and easily leaked (e.g., committed to source
    control). GCP-managed short-lived credentials are significantly safer.
    """
    findings = []
    print("[*] GCP: Checking for user-managed Service Account keys (CIS 1.4)...")

    project_id = _get_default_project_id()
    if not project_id:
        return findings

    service_accounts = run_gcp_command(
        f"gcloud iam service-accounts list --project={project_id} --format=json"
    )
    if not service_accounts:
        return findings

    for sa in service_accounts:
        email = sa.get("email")
        if not email:
            continue

        keys = run_gcp_command(
            f"gcloud iam service-accounts keys list "
            f"--iam-account={email} --project={project_id} --format=json"
        )
        if not keys:
            continue

        for key in keys:
            if key.get("keyType") == "USER_MANAGED":
                key_id_short = key.get("name", "").split("/")[-1][:12] + "..."
                findings.append({
                    "Cloud Provider": "GCP",
                    "Resource ID / Name": f"{email} (Key: {key_id_short})",
                    "Finding": (
                        "User-managed service account key detected. "
                        "These long-lived credentials are a high risk for key leakage."
                    ),
                    "Severity": "High",
                    "CIS Benchmark": "CIS GCP 1.4",
                    "Mitigation Strategy": (
                        "Delete user-managed keys and use GCP-managed short-lived credentials "
                        f"(Workload Identity Federation) instead. To delete: "
                        f"gcloud iam service-accounts keys delete <KEY_ID> "
                        f"--iam-account={email} --project={project_id}"
                    ),
                    "Status": "Open",
                })

    return findings


# ---------------------------------------------------------------------------
# CIS GCP 2.1 — Cloud Audit Logs
# ---------------------------------------------------------------------------

def check_gcp_audit_logging():
    """
    CIS GCP 2.1: Ensure that Cloud Audit Logging is configured properly across
    all services (Admin Activity logs must always be enabled).

    Without audit logs, there is no forensic trail to investigate security incidents
    or detect unauthorized API calls.
    """
    findings = []
    print("[*] GCP: Checking Cloud Audit Log configuration (CIS 2.1)...")

    project_id = _get_default_project_id()
    if not project_id:
        return findings

    policy = run_gcp_command(
        f"gcloud projects get-iam-policy {project_id} --format=json"
    )
    if not policy:
        return findings

    audit_configs = policy.get("auditConfigs", [])

    if not audit_configs:
        findings.append({
            "Cloud Provider": "GCP",
            "Resource ID / Name": project_id,
            "Finding": (
                "No audit log configuration found for this project. "
                "Admin Activity logs may not be enabled for all services."
            ),
            "Severity": "High",
            "CIS Benchmark": "CIS GCP 2.1",
            "Mitigation Strategy": (
                "Enable audit logging for all services via: "
                "gcloud projects get-iam-policy <PROJECT_ID> and add an "
                "'auditConfigs' entry for 'allServices' with ADMIN_READ, "
                "DATA_READ, and DATA_WRITE log types enabled."
            ),
            "Status": "Open",
        })
        return findings

    # Check if 'allServices' has full audit logging enabled
    all_services_config = next(
        (c for c in audit_configs if c.get("service") == "allServices"), None
    )

    if not all_services_config:
        findings.append({
            "Cloud Provider": "GCP",
            "Resource ID / Name": project_id,
            "Finding": (
                "Audit logging is not configured for 'allServices'. "
                "Some GCP services may not be logging admin or data access events."
            ),
            "Severity": "Medium",
            "CIS Benchmark": "CIS GCP 2.1",
            "Mitigation Strategy": (
                "Add an 'allServices' entry to your project's audit log config to "
                "ensure comprehensive coverage across all GCP APIs."
            ),
            "Status": "Open",
        })

    return findings


# ---------------------------------------------------------------------------
# CIS GCP 5.2 — Cloud Storage Uniform Bucket-Level Access
# ---------------------------------------------------------------------------

def check_gcp_storage_uniform_access():
    """
    CIS GCP 5.2: Ensure that Cloud Storage buckets have Uniform Bucket-Level Access enabled.

    Without uniform access, legacy ACLs can grant unintended public access to objects
    even when bucket-level IAM policies appear restrictive.
    """
    findings = []
    print("[*] GCP: Checking Storage Buckets for Uniform Bucket-Level Access (CIS 5.2)...")

    buckets = run_gcp_command("gcloud storage buckets list --format=json")
    if not buckets:
        return findings

    for bucket in buckets:
        name = bucket.get("name", "Unknown")
        iam_config = bucket.get("iamConfiguration", {})
        uniform_access = (
            iam_config.get("uniformBucketLevelAccess", {}).get("enabled", False)
        )

        if not uniform_access:
            findings.append({
                "Cloud Provider": "GCP",
                "Resource ID / Name": name,
                "Finding": (
                    f"Storage bucket '{name}' does not have Uniform Bucket-Level Access enabled. "
                    "Legacy ACLs may grant unintended access to individual objects."
                ),
                "Severity": "Medium",
                "CIS Benchmark": "CIS GCP 5.2",
                "Mitigation Strategy": (
                    f"Enable uniform access: "
                    f"gcloud storage buckets update gs://{name} --uniform-bucket-level-access"
                ),
                "Status": "Open",
            })

    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_gcp_checks():
    """Execute all GCP CIS checks and return a consolidated list of findings."""
    all_findings = []
    all_findings.extend(check_gcp_iam_service_account_keys())
    all_findings.extend(check_gcp_audit_logging())
    all_findings.extend(check_gcp_storage_uniform_access())
    return all_findings
