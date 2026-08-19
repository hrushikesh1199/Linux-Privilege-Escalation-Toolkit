import unittest

from modules.system_info import SystemInfoScanner
from modules.suid_scanner import SUIDScanner


class TestSystemInfo(unittest.TestCase):

    def test_scan_returns_dictionary(self):
        scanner = SystemInfoScanner()
        result = scanner.scan()

        self.assertIsInstance(result, dict)

    def test_kernel_information_exists(self):
        scanner = SystemInfoScanner()
        result = scanner.scan()

        self.assertIn("kernel", result)


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


if __name__ == "__main__":
    unittest.main()