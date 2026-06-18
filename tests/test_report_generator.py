"""
Tests for modules/report_generator.py

Verifies CSV and HTML report generation without touching the real filesystem
using temporary directories.
"""

import csv
import os
import tempfile
import unittest

from modules.report_generator import generate_csv_report, generate_html_report


SAMPLE_FINDINGS = [
    {
        "Cloud Provider": "AWS",
        "Resource ID / Name": "my-bucket",
        "Finding": "S3 bucket has no Public Access Block configuration.",
        "Severity": "Critical",
        "CIS Benchmark": "CIS AWS 2.1.1",
        "Mitigation Strategy": "Run: aws s3api put-public-access-block ...",
        "Status": "Open",
    },
    {
        "Cloud Provider": "Azure",
        "Resource ID / Name": "prod-storage",
        "Finding": "Storage Account does not enforce HTTPS.",
        "Severity": "High",
        "CIS Benchmark": "CIS Azure 3.1",
        "Mitigation Strategy": "Run: az storage account update --https-only true",
        "Status": "Open",
    },
    {
        "Cloud Provider": "GCP",
        "Resource ID / Name": "my-gcp-bucket",
        "Finding": "Uniform Bucket-Level Access not enabled.",
        "Severity": "Medium",
        "CIS Benchmark": "CIS GCP 5.2",
        "Mitigation Strategy": "gcloud storage buckets update ...",
        "Status": "Open",
    },
]


class TestGenerateCsvReport(unittest.TestCase):

    def test_creates_csv_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_csv_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))

    def test_csv_has_correct_headers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_csv_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                self.assertIn("Cloud Provider", reader.fieldnames)
                self.assertIn("Severity", reader.fieldnames)
                self.assertIn("Mitigation Strategy", reader.fieldnames)

    def test_csv_row_count_matches_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_csv_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), len(SAMPLE_FINDINGS))

    def test_csv_sorted_by_severity(self):
        """Critical findings should appear before High, then Medium."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_csv_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["Severity"], "Critical")
            self.assertEqual(rows[1]["Severity"], "High")
            self.assertEqual(rows[2]["Severity"], "Medium")

    def test_empty_findings_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_csv_report([], output_dir=tmpdir)
            self.assertIsNone(result)

    def test_output_directory_created_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            new_subdir = os.path.join(tmpdir, "reports", "new")
            generate_csv_report(SAMPLE_FINDINGS, output_dir=new_subdir)
            self.assertTrue(os.path.isdir(new_subdir))

    def test_filename_starts_with_risk_register(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_csv_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            basename = os.path.basename(path)
            self.assertTrue(basename.startswith("Risk_Register_"))

    def test_filename_ends_with_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_csv_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            self.assertTrue(path.endswith(".csv"))


class TestGenerateHtmlReport(unittest.TestCase):

    def test_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_html_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))

    def test_html_contains_provider_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_html_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("AWS", content)
            self.assertIn("Azure", content)
            self.assertIn("GCP", content)

    def test_html_contains_severity_levels(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_html_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("Critical", content)
            self.assertIn("High", content)
            self.assertIn("Medium", content)

    def test_html_is_valid_structure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_html_report(SAMPLE_FINDINGS, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("<table>", content)

    def test_empty_findings_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = generate_html_report([], output_dir=tmpdir)
            self.assertIsNone(result)

    def test_html_escapes_special_characters(self):
        """Mitigation strategies with < > & should not break the HTML."""
        xss_findings = [
            {
                "Cloud Provider": "AWS",
                "Resource ID / Name": "<bucket & name>",
                "Finding": "Test finding with <special> chars & symbols.",
                "Severity": "High",
                "CIS Benchmark": "CIS AWS 1.1",
                "Mitigation Strategy": "Use 'aws' --flag=\"value\" & verify",
                "Status": "Open",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generate_html_report(xss_findings, output_dir=tmpdir)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            # Raw angle brackets should NOT appear in the body
            self.assertNotIn("<bucket", content)
            # Escaped versions should be present
            self.assertIn("&lt;", content)
            self.assertIn("&gt;", content)


if __name__ == "__main__":
    unittest.main()
