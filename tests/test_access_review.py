import tempfile
import unittest
from datetime import date
from pathlib import Path

from access_review import load_users, review_users, write_csv
from data.generate_users import HEADER, generate_users, write_users


class AccessReviewTests(unittest.TestCase):
    def make_user(self, **overrides):
        user = {"user_id": "U1", "username": "test.user", "full_name": "Test User", "department": "Engineering", "title": "Software Engineer", "manager": "Manager", "status": "Active", "employment_status": "Active", "account_created": "2024-01-01", "termination_date": "", "last_login": "2026-09-01", "mfa_enabled": "true", "entitlements": ["Developer"]}
        user.update(overrides)
        return user

    def test_generated_population_and_headers(self):
        users = generate_users()
        self.assertEqual(len(users), 750)
        self.assertGreater(len(users), 500)
        self.assertEqual(list(users[0]), HEADER)

    def test_generator_rejects_small_population(self):
        with self.assertRaises(ValueError): generate_users(500)

    def test_stale_and_inactive_access_are_flagged(self):
        findings = review_users([self.make_user(last_login="2026-01-01")], date(2026, 9, 19), stale_days=90)
        self.assertIn("stale_account", {finding.rule for finding in findings})
        findings = review_users([self.make_user(status="Disabled", employment_status="Terminated", entitlements=["Production Admin"])], date(2026, 9, 19))
        self.assertIn("inactive_employment_status", {finding.rule for finding in findings})

    def test_csv_round_trip_uses_requested_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.csv"
            write_users(generate_users(501), path)
            with path.open(newline="", encoding="utf-8") as handle:
                self.assertEqual(next(__import__("csv").reader(handle)), HEADER)
            self.assertEqual(list(load_users(path)[0]), HEADER)

    def test_conflicts_and_mfa_are_flagged(self):
        findings = review_users([self.make_user(department="Finance", entitlements=["Finance Requester", "Finance Approver"]), self.make_user(user_id="U2", username="admin", entitlements=["Production Admin"], mfa_enabled="false")], date(2026, 9, 19))
        rules = {finding.rule for finding in findings}
        self.assertIn("segregation_of_duties", rules)
        self.assertIn("privileged_without_mfa", rules)


if __name__ == "__main__": unittest.main()
