"""
report_generator.py
--------------------
Generates Risk Register outputs from the consolidated list of audit findings.

Supported formats:
    - CSV  : Machine-readable spreadsheet for ticketing/tracking systems
    - HTML : Human-readable, colour-coded report for stakeholder review

Both formats are saved to the configured output directory (default: reports/).
"""

import csv
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

REPORT_HEADERS = [
    "Cloud Provider",
    "Resource ID / Name",
    "Finding",
    "Severity",
    "CIS Benchmark",
    "Mitigation Strategy",
    "Status",
]

SEVERITY_COLORS = {
    "Critical": "#e53e3e",   # red
    "High":     "#dd6b20",   # orange
    "Medium":   "#d69e2e",   # amber
    "Low":      "#38a169",   # green
}

SEVERITY_BG = {
    "Critical": "#fff5f5",
    "High":     "#fffaf0",
    "Medium":   "#fffff0",
    "Low":      "#f0fff4",
}


def _sort_findings(findings):
    """Return findings sorted by severity (Critical → Low)."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("Severity", "Low"), 99),
    )


def _ensure_output_dir(output_dir):
    """Create the output directory if it does not already exist."""
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)


def _make_filepath(output_dir, prefix, extension):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.{extension}"
    return os.path.join(output_dir, filename) if output_dir else filename


# ---------------------------------------------------------------------------
# CSV Report
# ---------------------------------------------------------------------------

def generate_csv_report(findings, output_dir="reports"):
    """
    Write all findings to a timestamped CSV Risk Register.

    Args:
        findings   : list of finding dicts from the cloud check modules.
        output_dir : directory to write the file into (created if missing).

    Returns:
        str: absolute path to the generated file, or None on failure.
    """
    if not findings:
        print("[i] No findings to report.")
        return None

    _ensure_output_dir(output_dir)
    file_path = _make_filepath(output_dir, "Risk_Register", "csv")
    sorted_findings = _sort_findings(findings)

    try:
        with open(file_path, mode="w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=REPORT_HEADERS)
            writer.writeheader()
            for finding in sorted_findings:
                writer.writerow(finding)
        return file_path
    except Exception as e:
        print(f"[-] Error generating CSV report: {e}")
        return None


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

def generate_html_report(findings, output_dir="reports"):
    """
    Write all findings to a timestamped, styled HTML Risk Register.

    The report includes:
      - Executive summary counts by provider and severity
      - Full findings table with colour-coded severity badges

    Args:
        findings   : list of finding dicts from the cloud check modules.
        output_dir : directory to write the file into (created if missing).

    Returns:
        str: absolute path to the generated file, or None on failure.
    """
    if not findings:
        return None

    _ensure_output_dir(output_dir)
    file_path = _make_filepath(output_dir, "Risk_Register", "html")
    sorted_findings = _sort_findings(findings)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Build summary stats ---
    total = len(sorted_findings)
    by_severity = {s: 0 for s in SEVERITY_ORDER}
    for f in sorted_findings:
        sev = f.get("Severity", "Low")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    summary_cards_html = ""
    for sev, count in by_severity.items():
        color = SEVERITY_COLORS[sev]
        summary_cards_html += f"""
        <div class="card" style="border-left: 5px solid {color};">
            <div class="card-count" style="color: {color};">{count}</div>
            <div class="card-label">{sev}</div>
        </div>"""

    # --- Build findings table rows ---
    rows_html = ""
    for finding in sorted_findings:
        sev = finding.get("Severity", "Low")
        color = SEVERITY_COLORS.get(sev, "#718096")
        bg = SEVERITY_BG.get(sev, "#ffffff")
        provider = finding.get("Cloud Provider", "")

        provider_badge_colors = {
            "AWS":   "#FF9900",
            "Azure": "#0078D4",
            "GCP":   "#4285F4",
        }
        p_color = provider_badge_colors.get(provider, "#718096")

        rows_html += f"""
        <tr style="background: {bg};">
            <td><span class="badge" style="background:{p_color};">{provider}</span></td>
            <td class="mono">{_esc(finding.get("Resource ID / Name", ""))}</td>
            <td>{_esc(finding.get("Finding", ""))}</td>
            <td><span class="badge sev-badge" style="background:{color};">{sev}</span></td>
            <td class="mono">{_esc(finding.get("CIS Benchmark", ""))}</td>
            <td class="mitigation">{_esc(finding.get("Mitigation Strategy", ""))}</td>
            <td><span class="status-badge">{_esc(finding.get("Status", "Open"))}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security Risk Register</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f7fafc;
            color: #2d3748;
            padding: 2rem;
        }}
        header {{
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            color: white;
            padding: 2rem 2.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}
        header h1 {{ font-size: 1.8rem; font-weight: 700; margin-bottom: 0.25rem; }}
        header p  {{ opacity: 0.7; font-size: 0.9rem; }}
        .summary {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 1.25rem 1.75rem;
            flex: 1;
            min-width: 120px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }}
        .card-count {{ font-size: 2.2rem; font-weight: 800; }}
        .card-label {{ font-size: 0.85rem; color: #718096; margin-top: 0.2rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .total-card {{
            background: #1a202c;
            color: white;
            border-radius: 10px;
            padding: 1.25rem 1.75rem;
            flex: 1;
            min-width: 120px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }}
        .total-card .card-count {{ font-size: 2.2rem; font-weight: 800; color: white; }}
        .total-card .card-label {{ color: rgba(255,255,255,0.6); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .table-wrapper {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }}
        thead tr {{
            background: #2d3748;
            color: white;
        }}
        th {{
            padding: 0.85rem 1rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid #edf2f7;
            vertical-align: top;
        }}
        tr:last-child td {{ border-bottom: none; }}
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 9999px;
            color: white;
            font-size: 0.72rem;
            font-weight: 700;
            white-space: nowrap;
        }}
        .sev-badge {{ padding: 0.25rem 0.7rem; }}
        .status-badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            background: #fed7d7;
            color: #c53030;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .mono {{ font-family: 'Courier New', monospace; font-size: 0.8rem; }}
        .mitigation {{ max-width: 320px; word-break: break-word; font-size: 0.82rem; color: #4a5568; }}
        footer {{
            text-align: center;
            margin-top: 2rem;
            font-size: 0.8rem;
            color: #a0aec0;
        }}
    </style>
</head>
<body>
    <header>
        <h1>☁️ Cloud Security Risk Register</h1>
        <p>Generated: {generated_at} &nbsp;|&nbsp; Total Findings: {total} &nbsp;|&nbsp; Based on CIS Benchmarks</p>
    </header>

    <div class="summary">
        <div class="total-card">
            <div class="card-count">{total}</div>
            <div class="card-label">Total Findings</div>
        </div>
        {summary_cards_html}
    </div>

    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>Provider</th>
                    <th>Resource</th>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>CIS Ref</th>
                    <th>Mitigation</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>

    <footer>
        <p>Cloud Security Configuration Auditor &mdash; CIS Benchmark Aligned</p>
    </footer>
</body>
</html>"""

    try:
        with open(file_path, mode="w", encoding="utf-8") as fh:
            fh.write(html)
        return file_path
    except Exception as e:
        print(f"[-] Error generating HTML report: {e}")
        return None


def _esc(text):
    """Escape special HTML characters to prevent XSS in the report."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
