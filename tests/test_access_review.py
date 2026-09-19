import tempfile
import unittest
from datetime import date
from pathlib import Path

from access_review import load_users, review_users, write_csv
from data.generate_users import generate_users


class AccessReviewTests(unittest.TestCase):
    def make_user(self, **overrides):
        user = {
            "user_id": "U1", "name": "Test User", "email": "u@example.test",
            "department": "Engineering", "manager": "Manager",
            "employment_status": "Active", "last_login": "2026-09-01",
            "roles": ["Developer"],
        }
        user.update(overrides)
        return user

    def test_generated_population_exceeds_500_users(self):
        users = generate_users()
        self.assertEqual(len(users), 750)
        self.assertGreater(len(users), 500)

    def test_generator_rejects_small_population(self):
        with self.assertRaises(ValueError):
            generate_users(500)

    def test_stale_active_account_is_flagged(self):
        findings = review_users([self.make_user(last_login="2026-01-01")], date(2026, 9, 19), stale_days=90)
        self.assertIn("stale_account", {finding.rule for finding in findings})

    def test_terminated_user_and_privileged_access_are_flagged(self):
        findings = review_users([self.make_user(employment_status="Terminated", roles=["Production Admin"])], date(2026, 9, 19))
        rules = {finding.rule for finding in findings}
        self.assertIn("inactive_employment_status", rules)
        self.assertIn("stale_privileged_access", rules)

    def test_conflicting_roles_are_flagged(self):
        findings = review_users([self.make_user(department="Finance", roles=["Finance Requester", "Finance Approver"])], date(2026, 9, 19))
        self.assertIn("segregation_of_duties", {finding.rule for finding in findings})

    def test_role_limit_and_department_mismatch_are_flagged(self):
        roles = ["Developer", "Read Only", "Production Admin", "Security Administrator", "Help Desk", "CRM User"]
        findings = review_users([self.make_user(roles=roles)], date(2026, 9, 19), max_roles=5)
        rules = {finding.rule for finding in findings}
        self.assertIn("role_count_exceeded", rules)
        self.assertIn("department_mismatch", rules)

    def test_csv_output_has_headers(self):
        findings = review_users([self.make_user()], date(2026, 9, 19))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            write_csv(findings, path)
            self.assertTrue(path.exists())
            self.assertIn("finding_id", path.read_text())

    def test_csv_loader_splits_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.csv"
            path.write_text("user_id,name,email,department,manager,employment_status,last_login,roles\nU1,A,B,C,D,Active,2026-09-01,Developer;Read Only\n")
            self.assertEqual(load_users(path)[0]["roles"], ["Developer", "Read Only"])


if __name__ == "__main__":
    unittest.main()
