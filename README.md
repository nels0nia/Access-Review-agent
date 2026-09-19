# IAM Access Review Agent

A dependency-free Python prototype that simulates an Identity Governance and Administration (IGA) access review over a synthetic population of 750+ users.

## User CSV schema

Generated input CSVs use these exact headings:

```text
user_id,username,full_name,department,title,manager,status,employment_status,account_created,termination_date,last_login,mfa_enabled,entitlements
```

`entitlements` is a semicolon-separated list. Dates use `YYYY-MM-DD`; boolean `mfa_enabled` values are `true` or `false`.

## Generate and review users

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

The generator rejects populations of 500 or fewer and deliberately includes synthetic exceptions for testing. The identities use reserved `.test` email-free usernames and are not real people.

## What it checks

- Stale active accounts
- Terminated, suspended, disabled, or locked accounts retaining entitlements
- Stale privileged access
- Privileged access without MFA
- Excessive entitlements
- Segregation-of-duties conflicts
- Department/entitlement mismatches
- Invalid source dates

Reports contain finding ID, user identity, severity, rule, evidence, and recommended remediation. This simulation does not connect to an identity provider or disable accounts.

## Test

```bash
python -m unittest discover -s tests -v
```
