
import unittest

from analyze_failure import analyze_failure


class TestFailureAnalyzer(unittest.TestCase):

    def test_missing_dependency(self):
        result = analyze_failure(
            "ModuleNotFoundError: No module named 'requests'"
        )
        self.assertEqual(result["category"], "Missing dependency")

    def test_permission_error(self):
        result = analyze_failure("ERROR: Permission denied")
        self.assertEqual(
            result["category"],
            "Permission or authentication failure",
        )

    def test_network_timeout(self):
        result = analyze_failure("Connection timed out")
        self.assertEqual(
            result["category"],
            "Timeout or connectivity failure",
        )

    def test_test_failure(self):
        result = analyze_failure("AssertionError: test failed")
        self.assertEqual(result["category"], "Test failure")

    def test_missing_file(self):
        result = analyze_failure("No such file or directory")
        self.assertEqual(result["category"], "Missing file or path")

    def test_unknown_error(self):
        result = analyze_failure("Unexpected application problem")
        self.assertEqual(result["category"], "Unknown failure")

    def test_recommendation_is_provided(self):
        result = analyze_failure("ModuleNotFoundError: requests")
        self.assertTrue(result["fix"])

    def test_evidence_is_provided(self):
        result = analyze_failure("ModuleNotFoundError: requests")
        self.assertTrue(result["evidence"])


if __name__ == "__main__":
    unittest.main()
