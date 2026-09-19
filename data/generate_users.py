"""Generate a deterministic synthetic IAM population larger than 500 users."""

from __future__ import annotations

import argparse
import csv
from datetime import date, timedelta
from pathlib import Path

HEADER = [
    "user_id", "username", "full_name", "department", "title", "manager",
    "status", "employment_status", "account_created", "termination_date",
    "last_login", "mfa_enabled", "entitlements",
]
DEPARTMENTS = {
    "Engineering": ("Software Engineer", "Developer", "Production Admin"),
    "Finance": ("Financial Analyst", "Finance Requester", "Finance Approver"),
    "IT": ("IT Support Specialist", "Help Desk", "Read Only"),
    "HR": ("HR Analyst", "HR Analyst", "Read Only"),
    "Sales": ("Account Executive", "CRM User", "Read Only"),
    "Legal": ("Contract Specialist", "Contract Reviewer", "Read Only"),
}
MANAGERS = ["Ada Lovelace", "Grace Hopper", "Katherine Johnson", "Alan Turing"]


def generate_users(count: int = 750) -> list[dict[str, str]]:
    if count < 501:
        raise ValueError("count must be greater than 500")
    departments = list(DEPARTMENTS)
    users = []
    for number in range(1, count + 1):
        department = departments[(number - 1) % len(departments)]
        title, primary, secondary = DEPARTMENTS[department]
        status, employment_status, termination_date = "Active", "Active", ""
        last_login, entitlements = "2026-09-18", primary
        if number % 47 == 0:
            status, employment_status, termination_date = "Disabled", "Terminated", "2026-08-20"
            last_login, entitlements = "2026-08-20", primary
        elif number % 31 == 0:
            last_login, entitlements = "2025-12-01", f"{primary};{secondary}"
        elif number % 29 == 0:
            status, employment_status = "Locked", "Suspended"
            last_login = "2026-03-01"
        elif number % 37 == 0:
            entitlements = f"{primary};Production Admin;Security Administrator;Help Desk;CRM User;Read Only"
        account_created = date(2021, 1, 1) + timedelta(days=(number * 11) % 1800)
        users.append({
            "user_id": f"U{number:04d}",
            "username": f"user{number:04d}",
            "full_name": f"Synthetic User {number:04d}",
            "department": department,
            "title": title,
            "manager": MANAGERS[(number - 1) % len(MANAGERS)],
            "status": status,
            "employment_status": employment_status,
            "account_created": account_created.isoformat(),
            "termination_date": termination_date,
            "last_login": last_login,
            "mfa_enabled": "false" if number % 17 == 0 else "true",
            "entitlements": entitlements,
        })
    return users


def write_users(users: list[dict[str, str]], output: str | Path) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(users)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the synthetic IAM user population")
    parser.add_argument("--count", type=int, default=750)
    parser.add_argument("--output", default="data/users_generated.csv")
    args = parser.parse_args()
    write_users(generate_users(args.count), args.output)
    print(f"Wrote {args.count} synthetic users to {args.output}")
