"""Generate a deterministic synthetic IAM population larger than 500 users."""

from __future__ import annotations

import argparse
import csv
from datetime import date, timedelta
from pathlib import Path

HEADER = ["user_id", "name", "email", "department", "manager", "employment_status", "last_login", "roles"]
DEPARTMENTS = {
    "Engineering": ("Developer", "Production Admin"),
    "Finance": ("Finance Requester", "Finance Approver"),
    "IT": ("Help Desk", "Read Only"),
    "HR": ("HR Analyst", "Read Only"),
    "Sales": ("CRM User", "Read Only"),
    "Legal": ("Contract Reviewer", "Read Only"),
}
MANAGERS = ["Ada Lovelace", "Grace Hopper", "Katherine Johnson", "Alan Turing"]


def generate_users(count: int = 750) -> list[dict[str, str]]:
    if count < 501:
        raise ValueError("count must be greater than 500")
    departments = list(DEPARTMENTS)
    users = []
    for number in range(1, count + 1):
        department = departments[(number - 1) % len(departments)]
        primary, secondary = DEPARTMENTS[department]
        # Deliberately include realistic exceptions so the review has findings.
        if number % 47 == 0:
            status, last_login, roles = "Terminated", "2026-08-20", primary
        elif number % 31 == 0:
            status, last_login, roles = "Active", "2025-12-01", f"{primary};{secondary}"
        elif number % 29 == 0:
            status, last_login, roles = "Suspended", "2026-03-01", primary
        elif number % 37 == 0:
            status, last_login, roles = "Active", "2026-09-10", f"{primary};Production Admin;Security Administrator;Help Desk;CRM User;Read Only"
        else:
            status, last_login, roles = "Active", "2026-09-18", primary
        users.append({
            "user_id": f"U{number:04d}",
            "name": f"Synthetic User {number:04d}",
            "email": f"user{number:04d}@example.test",
            "department": department,
            "manager": MANAGERS[(number - 1) % len(MANAGERS)],
            "employment_status": status,
            "last_login": last_login,
            "roles": roles,
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
