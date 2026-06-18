# Contributing to Cloud Security Configuration Auditor

Thank you for your interest in contributing! This project is designed to be
extended easily — adding new CIS checks is straightforward.

---

## How to Add a New Check

1. **Choose the correct module** — `modules/aws_checks.py`, `modules/azure_checks.py`,
   or `modules/gcp_checks.py`.

2. **Write a function** following this pattern:

   ```python
   def check_<provider>_<what_you_check>():
       """
       CIS <PROVIDER> <CONTROL_ID>: Brief description.
       """
       findings = []
       print("[*] <Provider>: Checking <thing> (<CIS ref>)...")

       data = run_<provider>_command("cli command here --output json")
       if not data:
           return findings

       # ... your logic ...

       findings.append({
           "Cloud Provider": "<AWS | Azure | GCP>",
           "Resource ID / Name": "<resource identifier>",
           "Finding": "<clear description of the misconfiguration>",
           "Severity": "<Critical | High | Medium | Low>",
           "CIS Benchmark": "<CIS <PROVIDER> <CONTROL_ID>>",
           "Mitigation Strategy": "<specific remediation command or action>",
           "Status": "Open",
       })
       return findings
   ```

3. **Register the check** by adding it to the `run_all_<provider>_checks()` function
   at the bottom of the module.

4. **Write a test** in `tests/test_<provider>_checks.py`. Mock `subprocess.run` to
   simulate CLI output for both the vulnerable (finding expected) and secure
   (no finding expected) scenarios.

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v --cov=modules
```

All tests must pass before a pull request will be reviewed.

---

## Code Style

- Follow PEP 8 for all Python code.
- Add a docstring to every new check function explaining the CIS control it addresses.
- Use the existing `run_<provider>_command()` utility — do not call `subprocess` directly.
- Keep findings concise but informative. The `Mitigation Strategy` should include
  a runnable CLI command wherever possible.

---

## Reporting Security Issues

If you discover a security vulnerability in this tool itself, please **do not**
open a public GitHub issue. Instead, reach out privately so it can be addressed
responsibly before disclosure.
