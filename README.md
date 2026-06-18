# Cloud Security Configuration Auditor

[![Python CI](https://github.com/Patelprincein/Cloud-Security-Configuration-Auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Patelprincein/Cloud-Security-Configuration-Auditor/actions/workflows/ci.yml)
![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An automated cloud security configuration auditor that assesses **AWS**, **Azure**, and **GCP**
environments against **CIS (Center for Internet Security) Benchmark** controls.

Findings are exported as a timestamped **CSV** and **HTML Risk Register** — ready for
stakeholder review, remediation tracking, or a ticketing system.

---

## Features

| Provider | CIS Control | Check |
|----------|------------|-------|
| **AWS**   | CIS 1.5  | Root account MFA status |
| **AWS**   | CIS 1.10 | IAM user MFA for console users |
| **AWS**   | CIS 2.1  | S3 bucket Public Access Block |
| **AWS**   | CIS 3.1  | CloudTrail multi-region logging |
| **AWS**   | CIS 5.2/5.3 | Security Groups: open SSH / RDP |
| **Azure** | CIS 1.1  | Conditional Access / MFA policy |
| **Azure** | CIS 1.14 | Guest user account review |
| **Azure** | CIS 3.1  | Storage Account HTTPS enforcement |
| **Azure** | CIS 6.1/6.2 | NSG: open SSH / RDP ingress |
| **GCP**   | CIS 1.4  | Service Account user-managed keys |
| **GCP**   | CIS 2.1  | Cloud Audit Log configuration |
| **GCP**   | CIS 5.2  | Storage Bucket Uniform Access |

---

## Architecture

```
Cloud Security Configuration Review/
├── config_auditor.py        ← Main entry point (CLI argument parsing, orchestration)
├── modules/
│   ├── aws_checks.py        ← AWS CIS check functions
│   ├── azure_checks.py      ← Azure CIS check functions
│   ├── gcp_checks.py        ← GCP CIS check functions
│   └── report_generator.py  ← CSV + HTML Risk Register generation
├── tests/
│   ├── test_aws_checks.py
│   ├── test_azure_checks.py
│   ├── test_gcp_checks.py
│   └── test_report_generator.py
├── reports/                 ← Auto-created; timestamped reports saved here
├── .github/workflows/ci.yml ← GitHub Actions CI (Python 3.10 / 3.11 / 3.12)
├── requirements.txt
└── CONTRIBUTING.md
```

**Design decisions:**
- **CLI over SDK** — Raw JSON from the cloud CLIs allows rapid prototyping with minimal
  library dependencies. Adding a check is as simple as wrapping one CLI command.
- **Modular pattern** — Each provider lives in its own module. New CIS controls require
  only a new function and a test; no changes to the core runner.
- **No cloud credentials stored** — The tool relies entirely on the authenticated
  local CLI context (`aws configure`, `az login`, `gcloud auth login`).

---

## Prerequisites

| Tool | Install Guide |
|------|---------------|
| Python 3.10+ | [python.org](https://www.python.org/downloads/) |
| AWS CLI | [AWS Docs](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |
| Azure CLI (`az`) | [Microsoft Docs](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| Google Cloud SDK (`gcloud`) | [GCP Docs](https://cloud.google.com/sdk/docs/install) |

---

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/Patelprincein/Cloud-Security-Configuration-Auditor.git
cd Cloud-Security-Configuration-Review

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Authenticate with your cloud providers
aws configure                        # AWS
az login                             # Azure
gcloud auth login                    # GCP
gcloud config set project YOUR_ID   # GCP: set active project
```

---

## Usage

```bash
# Audit all three cloud providers
python config_auditor.py

# Audit a specific provider
python config_auditor.py --provider aws
python config_auditor.py --provider azure
python config_auditor.py --provider gcp
```

### Sample Terminal Output

```
============================================================
   Cloud Security Configuration Auditor
   Providers: AWS | Azure | GCP
   Based on CIS Benchmarks
============================================================

==> Starting AWS Configuration Review...
[*] AWS: Checking Root Account MFA status (CIS 1.5)...
[*] AWS: Checking IAM Users for MFA enablement (CIS 1.10)...
[*] AWS: Checking S3 Buckets for Public Access Block (CIS 2.1)...
[*] AWS: Checking CloudTrail multi-region logging (CIS 3.1)...
[*] AWS: Checking Security Groups for unrestricted SSH/RDP (CIS 5.2/5.3)...
[*] Completed AWS checks. Found 3 potential issue(s).

============================================================
   FINDINGS SUMMARY
============================================================
  Provider    Critical    High        Medium      Low         Total
------------------------------------------------------------
  AWS         1           2           0           0           3

==> Generating Risk Register reports...
[+] CSV Report  → reports/Risk_Register_20250618_041832.csv
[+] HTML Report → reports/Risk_Register_20250618_041832.html
```

### Risk Register Output

Reports are saved to the `reports/` folder (auto-created on first run).

**CSV columns:** Cloud Provider | Resource ID / Name | Finding | Severity | CIS Benchmark | Mitigation Strategy | Status

**HTML report** includes:
- Executive summary cards by severity level
- Colour-coded findings table (Critical → Red, High → Orange, Medium → Amber, Low → Green)
- Inline remediation CLI commands

---

## Running Tests

```bash
pytest tests/ -v --cov=modules --cov-report=term-missing
```

Tests use `unittest.mock` to simulate CLI output — **no live cloud account is needed**.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new CIS checks.

---

## License

[MIT](LICENSE)
