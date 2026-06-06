import unittest

from modules.system_info import SystemInfoScanner


class TestSystemInfo(unittest.TestCase):

    def test_scan_returns_dictionary(self):
        scanner = SystemInfoScanner()
        result = scanner.scan()

        self.assertIsInstance(result, dict)

    def test_kernel_information_exists(self):
        scanner = SystemInfoScanner()
        result = scanner.scan()

        self.assertIn("kernel", result)


if __name__ == "__main__":
    unittest.main()