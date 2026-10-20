"""Tests for dashboard-poll filtering in network request monitoring."""
import unittest

from models.request_policy import should_record_request


class RequestPolicyTests(unittest.TestCase):
    def test_known_dashboard_get_polls_are_not_counted_as_user_traffic(self):
        for path in (
            "/api/dashboard/summary",
            "/api/network/topology",
            "/api/live-threat",
            "/api/incidents",
            "/api/health",
            "/api/notifications/unread-count",
        ):
            with self.subTest(path=path):
                self.assertFalse(should_record_request("GET", path))
                self.assertFalse(should_record_request("get", path + "/"))

    def test_mutating_calls_are_always_monitored_even_on_poll_paths(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertTrue(should_record_request(method, "/api/live-threat"))

    def test_unlisted_reads_and_incident_details_are_monitored(self):
        self.assertTrue(should_record_request("GET", "/api/login-history"))
        self.assertTrue(should_record_request("GET", "/api/incidents/INC-123"))

    def test_non_api_requests_are_not_accidentally_excluded_by_policy(self):
        self.assertTrue(should_record_request("GET", "/dashboard/summary"))


if __name__ == "__main__":
    unittest.main()
