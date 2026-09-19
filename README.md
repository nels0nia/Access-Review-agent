# IAM Access Review Agent

A dependency-free Python prototype that simulates an Identity Governance and Administration (IGA) access review. It evaluates a fake user population and emits auditable findings suitable for manager recertification workflows.

## Generate a population larger than 500 users

The repository includes a deterministic generator that creates **750 synthetic users** by default. The identities use reserved `.test` email addresses.

```bash
python data/generate_users.py
# creates data/users_generated.csv with 750 users
```

You can choose another population size, but it must be greater than 500:

```bash
python data/generate_users.py --count 1000 --output data/users_1000.csv
```

## What it checks

- **Stale accounts:** active users whose last login is older than the configured threshold.
- **Inactive employment status:** terminated or suspended users who still have roles.
- **Stale privileged access:** privileged roles on stale, suspended, or terminated accounts.
- **Over-provisioning:** users with more than the maximum role count.
- **Segregation of duties:** conflicting role pairs such as `Finance Requester` + `Finance Approver`.
- **Department mismatch:** roles outside the normal department allowlist.
- **Invalid source data:** malformed last-login dates are reported instead of silently skipped.

This is a simulation only. It does not connect to an identity provider or disable accounts.

## Run it against the generated population

Requires Python 3.10 or newer.

```bash
python data/generate_users.py --count 750 --output data/users_generated.csv
python access_review.py \
  --input data/users_generated.csv \
  --output reports/access_review_report.csv \
  --summary-output reports/access_review_summary.json \
  --stale-days 90 \
  --max-roles 5 \
  --as-of 2026-09-19
```

The report contains one row per finding with a severity, rule, evidence, and recommended remediation. The summary contains totals by severity and rule. Output directories are created automatically.

## Test

```bash
python -m unittest discover -s tests -v
```

## Input format

`roles` is a semicolon-separated list. Dates use ISO `YYYY-MM-DD` format. The included records use reserved `.test` email addresses and fictionalized sample identities.

## Extending the agent

For a production implementation, replace the CSV loader with connectors for HR, directory, and entitlement systems; externalize role policies; add approval evidence and reviewer assignments; and persist finding status and remediation history. Keep the review date (`--as-of`) fixed for repeatable audit runs.
