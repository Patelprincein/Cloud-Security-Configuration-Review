"""
config_auditor.py
-----------------
Main entry point for the Cloud Security Configuration Auditor.

Supports auditing AWS, Azure, and GCP environments against CIS Benchmarks.
Generates a timestamped Risk Register CSV (and optional HTML) in the reports/ folder.

Usage:
    python config_auditor.py                  # Audit all providers
    python config_auditor.py --provider aws   # AWS only
    python config_auditor.py --provider azure # Azure only
    python config_auditor.py --provider gcp   # GCP only
"""

import sys
import os
import argparse
from colorama import init, Fore, Style
from modules.aws_checks import run_all_aws_checks
from modules.azure_checks import run_all_azure_checks
from modules.gcp_checks import run_all_gcp_checks
from modules.report_generator import generate_csv_report, generate_html_report

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

REPORTS_DIR = "reports"


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "   Cloud Security Configuration Auditor")
    print(Fore.CYAN + Style.BRIGHT + "   Providers: AWS | Azure | GCP")
    print(Fore.CYAN + Style.BRIGHT + "   Based on CIS Benchmarks")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60 + "\n")


def print_summary(all_findings):
    """Print a formatted summary table of findings by provider and severity."""
    if not all_findings:
        return

    # Count findings by provider and severity
    summary = {}
    severities = ["Critical", "High", "Medium", "Low"]
    providers = sorted({f.get("Cloud Provider", "Unknown") for f in all_findings})

    for provider in providers:
        summary[provider] = {sev: 0 for sev in severities}
        for finding in all_findings:
            if finding.get("Cloud Provider") == provider:
                sev = finding.get("Severity", "Low")
                if sev in summary[provider]:
                    summary[provider][sev] += 1

    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "   FINDINGS SUMMARY")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)

    # Header row
    col_w = 12
    header = f"  {'Provider':<12}" + "".join(f"{s:<{col_w}}" for s in severities) + f"{'Total':<8}"
    print(Fore.WHITE + Style.BRIGHT + header)
    print(Fore.WHITE + "-" * 60)

    severity_colors = {
        "Critical": Fore.RED,
        "High": Fore.YELLOW,
        "Medium": Fore.MAGENTA,
        "Low": Fore.CYAN,
    }

    for provider in providers:
        row_total = sum(summary[provider].values())
        row = f"  {provider:<12}"
        for sev in severities:
            count = summary[provider][sev]
            color = severity_colors[sev] if count > 0 else Fore.WHITE
            row += color + f"{count:<{col_w}}" + Style.RESET_ALL
        row += Fore.WHITE + Style.BRIGHT + f"{row_total:<8}"
        print(row)

    print(Fore.WHITE + "-" * 60)
    print(Fore.WHITE + Style.BRIGHT + f"  {'TOTAL':<12}" + f"{len(all_findings):<8}" + "\n")


def ensure_reports_dir():
    """Create the reports/ output directory if it doesn't already exist."""
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Automated cloud security configuration auditor for AWS, Azure, and GCP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python config_auditor.py                   # Audit all providers\n"
            "  python config_auditor.py --provider aws    # AWS only\n"
            "  python config_auditor.py --provider azure  # Azure only\n"
            "  python config_auditor.py --provider gcp    # GCP only\n"
        ),
    )
    parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp", "all"],
        default="all",
        help="Cloud provider to audit. Default: all",
    )
    args = parser.parse_args()

    ensure_reports_dir()
    all_findings = []

    # --- AWS ---
    if args.provider in ["aws", "all"]:
        print(Fore.YELLOW + "==> Starting AWS Configuration Review...")
        try:
            aws_findings = run_all_aws_checks()
            all_findings.extend(aws_findings)
            print(Fore.GREEN + f"[*] Completed AWS checks. Found {len(aws_findings)} potential issue(s).\n")
        except Exception as e:
            print(Fore.RED + f"[-] Failed to complete AWS checks: {e}\n")
            print(Fore.CYAN + "    Ensure AWS CLI is configured: run 'aws configure' or set env vars.\n")

    # --- Azure ---
    if args.provider in ["azure", "all"]:
        print(Fore.YELLOW + "==> Starting Azure Configuration Review...")
        try:
            azure_findings = run_all_azure_checks()
            all_findings.extend(azure_findings)
            print(Fore.GREEN + f"[*] Completed Azure checks. Found {len(azure_findings)} potential issue(s).\n")
        except Exception as e:
            print(Fore.RED + f"[-] Failed to complete Azure checks: {e}\n")
            print(Fore.CYAN + "    Ensure Azure CLI is authenticated: run 'az login'.\n")

    # --- GCP ---
    if args.provider in ["gcp", "all"]:
        print(Fore.YELLOW + "==> Starting GCP Configuration Review...")
        try:
            gcp_findings = run_all_gcp_checks()
            all_findings.extend(gcp_findings)
            print(Fore.GREEN + f"[*] Completed GCP checks. Found {len(gcp_findings)} potential issue(s).\n")
        except Exception as e:
            print(Fore.RED + f"[-] Failed to complete GCP checks: {e}\n")
            print(Fore.CYAN + "    Ensure GCloud SDK is authenticated: run 'gcloud auth login'.\n")

    # --- Generate Reports ---
    if all_findings:
        print_summary(all_findings)
        print(Fore.YELLOW + "==> Generating Risk Register reports...")

        csv_path = generate_csv_report(all_findings, output_dir=REPORTS_DIR)
        if csv_path:
            print(Fore.GREEN + f"[+] CSV Report  → {csv_path}")

        html_path = generate_html_report(all_findings, output_dir=REPORTS_DIR)
        if html_path:
            print(Fore.GREEN + f"[+] HTML Report → {html_path}")

        print(Fore.CYAN + "\n[i] Review the reports above for detailed remediation steps.")
    else:
        print(Fore.GREEN + "[+] Audit complete. No misconfigurations found.")
        print(Fore.CYAN + "[i] If this is unexpected, verify CLI authentication:")
        print(Fore.CYAN + "    AWS:   aws configure  /  aws sts get-caller-identity")
        print(Fore.CYAN + "    Azure: az login       /  az account show")
        print(Fore.CYAN + "    GCP:   gcloud auth login  /  gcloud config list")


if __name__ == "__main__":
    main()
