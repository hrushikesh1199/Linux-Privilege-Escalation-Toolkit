import unittest
from datetime import datetime

from modules.system_info import SystemInfoScanner
from modules.suid_scanner import SUIDScanner
from modules.report_generator import ReportGenerator
from unittest.mock import patch
import subprocess


class TestSystemInfo(unittest.TestCase):

    def test_total_findings_empty(self):
        generator = ReportGenerator(
            {},
            datetime.now(),
            0.0
        )

        self.assertEqual(generator.total_findings(), 0)

    def test_scan_returns_dictionary(self):
        scanner = SystemInfoScanner()
        result = scanner.scan()

        self.assertIsInstance(result, dict)

    def test_kernel_information_exists(self):
        scanner = SystemInfoScanner()
        result = scanner.scan()

        self.assertIn("kernel", result)


class TestReportGenerator(unittest.TestCase):



    def test_export_txt_creates_report(self):
        import tempfile
        import os

        findings = {
            "System Information": {
                "hostname": "test-host",
                "kernel": "6.1.0",
                "whoami": "tester"
            },
            "SUID/SGID Binaries": {
                "suid_binaries": [],
                "sgid_binaries": [],
                "exploitable_suid": [],
                "unexpected_suid": [],
                "capabilities": ["python3 cap_setuid+ep"]
            }
        }

        generator = ReportGenerator(
            findings,
            datetime.now(),
            1.5
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(temp_dir, "audit.txt")

            generator.export_txt(report_path)

            self.assertTrue(os.path.exists(report_path))

            with open(report_path, "r", encoding="utf-8") as file:
                report = file.read()

            self.assertIn("LINUX PRIVILEGE ESCALATION AUDIT REPORT", report)
            self.assertIn("SYSTEM INFORMATION", report)
            self.assertIn("SUID / SGID ANALYSIS", report)
            self.assertIn("Linux Capabilities:", report)
            self.assertIn("python3 cap_setuid+ep", report)

    def test_total_findings_counts_lists(self):
        findings = {
            "SUID/SGID Binaries": {
                "suid_binaries": [{"path": "/usr/bin/example"}],
                "sgid_binaries": [{"path": "/usr/bin/example2"}],
                "exploitable_suid": [],
                "unexpected_suid": [],
                "capabilities": ["cap_setuid+ep"]
            }
        }

        generator = ReportGenerator(
            findings,
            datetime.now(),
            1.0
        )

        self.assertEqual(generator.total_findings(), 3)

    def test_suid_report_includes_capabilities(self):
        findings = {
            "SUID/SGID Binaries": {
                "suid_binaries": [],
                "sgid_binaries": [],
                "exploitable_suid": [],
                "unexpected_suid": [],
                "capabilities": ["/usr/bin/python3 cap_setuid+ep"]
            }
        }

        generator = ReportGenerator(
            findings,
            datetime.now(),
            1.0
        )

        report = generator._format_suid()

        self.assertIn("Linux Capabilities:", report)
        self.assertIn("cap_setuid+ep", report)        


class TestSUIDScanner(unittest.TestCase):

    def test_scan_returns_expected_structure(self):
        scanner = SUIDScanner()
        result = scanner.scan()

        self.assertIsInstance(result, dict)
        self.assertIn("suid_binaries", result)
        self.assertIn("sgid_binaries", result)
        self.assertIn("exploitable_suid", result)
        self.assertIn("unexpected_suid", result)
        self.assertIn("capabilities", result)

    @patch("modules.suid_scanner.subprocess.run")
    def test_run_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="find /",
            timeout=60
        )

        scanner = SUIDScanner()
        result = scanner._run("find /")

        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()