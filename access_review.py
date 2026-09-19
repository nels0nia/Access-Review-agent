"""IAM access review agent for synthetic identity and access data.

The module is intentionally dependency-free so it can be used in a scheduled job,
CI pipeline, or imported by another governance workflow.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_STALE_DAYS = 90
DEFAULT_MAX_ROLES = 5
PRIVILEGED_ROLES = {"Global Administrator", "Security Administrator", "Production Admin"}
CONFLICTING_ROLE_PAIRS = {
    frozenset({"Finance Requester", "Finance Approver"}),
    frozenset({"Developer", "Production Admin"}),
}
DEPARTMENT_ROLE_ALLOWLISTS = {
    "Finance": {"Finance Requester", "Finance Approver", "Read Only"},
    "Engineering": {"Developer", "Production Admin", "Read Only"},
    "IT": {"Help Desk", "Security Administrator", "Production Admin", "Read Only"},
    "HR": {"HR Analyst", "Read Only"},
    "Sales": {"CRM User", "Read Only"},
    "Legal": {"Contract Reviewer", "Read Only"},
}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    user_id: str
    user_name: str
    severity: str
    rule: str
    details: str
    recommended_action: str


def parse_date(value: str) -> date:
    return datetime.strptime(value.strip(), "%Y-%m-%d").date()


def load_users(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "user_id", "name", "email", "department", "manager",
            "employment_status", "last_login", "roles",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
        users = []
        for row in reader:
            row["roles"] = [role.strip() for role in row["roles"].split(";") if role.strip()]
            users.append(row)
        return users


def _finding(user: dict[str, str], severity: str, rule: str, details: str, action: str, number: int) -> Finding:
    return Finding(
        finding_id=f"AR-{number:04d}", user_id=user["user_id"], user_name=user["name"],
        severity=severity, rule=rule, details=details, recommended_action=action,
    )


def review_users(
    users: Iterable[dict[str, str]],
    as_of: date,
    stale_days: int = DEFAULT_STALE_DAYS,
    max_roles: int = DEFAULT_MAX_ROLES,
) -> list[Finding]:
    findings: list[Finding] = []
    next_number = 1
    for user in users:
        status = user["employment_status"].strip().lower()
        roles = set(user["roles"])
        try:
            last_login = parse_date(user["last_login"])
        except ValueError as exc:
            findings.append(_finding(user, "high", "invalid_last_login", str(exc), "Correct the source identity record.", next_number))
            next_number += 1
            continue
        inactive_days = (as_of - last_login).days

        if status in {"terminated", "suspended"} and roles:
            findings.append(_finding(user, "critical", "inactive_employment_status", f"{status.title()} user retains {len(roles)} role(s): {', '.join(sorted(roles))}.", "Disable the account and revoke all sessions and access.", next_number))
            next_number += 1
        elif status == "active" and inactive_days > stale_days:
            findings.append(_finding(user, "medium", "stale_account", f"No login for {inactive_days} days (threshold: {stale_days}).", "Validate employment and business need; disable or recertify the account.", next_number))
            next_number += 1

        if roles & PRIVILEGED_ROLES and (status != "active" or inactive_days > stale_days):
            privileged = ", ".join(sorted(roles & PRIVILEGED_ROLES))
            findings.append(_finding(user, "high", "stale_privileged_access", f"Privileged role(s) {privileged} belong to a non-current or stale account.", "Immediately remove privileged roles and investigate recent activity.", next_number))
            next_number += 1

        if len(roles) > max_roles:
            findings.append(_finding(user, "high", "role_count_exceeded", f"User has {len(roles)} roles (maximum expected: {max_roles}).", "Have the manager recertify each role and remove unnecessary access.", next_number))
            next_number += 1

        for pair in CONFLICTING_ROLE_PAIRS:
            if pair <= roles:
                findings.append(_finding(user, "high", "segregation_of_duties", f"Conflicting roles assigned together: {' + '.join(sorted(pair))}.", "Remove one side of the conflict or document an approved compensating control.", next_number))
                next_number += 1

        allowed = DEPARTMENT_ROLE_ALLOWLISTS.get(user["department"].strip())
        if allowed:
            unapproved = roles - allowed
            if unapproved:
                findings.append(_finding(user, "medium", "department_mismatch", f"Role(s) not normally approved for {user['department']}: {', '.join(sorted(unapproved))}.", "Obtain an exception approval or remove the unneeded role(s).", next_number))
                next_number += 1
    return findings


def write_csv(findings: Sequence[Finding], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(Finding.__dataclass_fields__))
        writer.writeheader()
        writer.writerows(asdict(item) for item in findings)


def write_summary(findings: Sequence[Finding], users_count: int, path: str | Path) -> None:
    summary = {
        "reviewed_users": users_count,
        "total_findings": len(findings),
        "by_severity": dict(Counter(item.severity for item in findings)),
        "by_rule": dict(Counter(item.rule for item in findings)),
        "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    }
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a synthetic IAM access review.")
    parser.add_argument("--input", default="data/users.csv", help="Input user CSV")
    parser.add_argument("--output", default="reports/access_review_report.csv", help="Finding CSV output")
    parser.add_argument("--summary-output", default="reports/access_review_summary.json", help="Summary JSON output")
    parser.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    parser.add_argument("--max-roles", type=int, default=DEFAULT_MAX_ROLES)
    parser.add_argument("--as-of", type=parse_date, default=date.today(), help="Review date (YYYY-MM-DD)")
    args = parser.parse_args()
    users = load_users(args.input)
    findings = review_users(users, args.as_of, args.stale_days, args.max_roles)
    write_csv(findings, args.output)
    write_summary(findings, len(users), args.summary_output)
    print(f"Reviewed {len(users)} users and generated {len(findings)} findings.")
    print(f"Findings: {args.output}\nSummary: {args.summary_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
