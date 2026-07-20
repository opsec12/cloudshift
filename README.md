# clouddrift

A zero-dependency CLI that detects unauthorized IAM drift in AWS accounts. Compares two IAM snapshots and surfaces new users, privilege escalation, policy changes, and trust policy mutations — before they become incidents.

## How it works

1. You snapshot your IAM state with the AWS CLI and store it as a baseline
2. At any point later, you snapshot again and run `clouddrift`
3. It diffs the two snapshots and flags anything that changed
4. Exits code 1 on CRITICAL or HIGH drift — blocks your CI/CD pipeline

## Rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `NEW_IAM_USER` | CRITICAL / MEDIUM | New IAM user created (CRITICAL if immediately given admin rights) |
| `IAM_USER_DELETED` | LOW | IAM user was deleted |
| `POLICY_ATTACHED_TO_USER` | CRITICAL / MEDIUM | New managed policy attached to a user |
| `POLICY_DETACHED_FROM_USER` | LOW | Managed policy removed from a user |
| `USER_GROUP_ADDED` | MEDIUM | User added to a new group |
| `NEW_IAM_ROLE` | HIGH / LOW | New IAM role created (HIGH if it has admin rights) |
| `POLICY_ATTACHED_TO_ROLE` | CRITICAL / MEDIUM | New managed policy attached to a role |
| `TRUST_POLICY_CHANGED` | HIGH | Role trust policy changed — someone new can now AssumeRole |

## Usage

```bash
# Step 1: capture baseline and store it somewhere safe (S3, git, Vault)
aws iam get-account-authorization-details > baseline.json

# Step 2: later, capture current state
aws iam get-account-authorization-details > current.json

# Step 3: detect drift
go run main.go baseline.json current.json

# Or build first
go build -o clouddrift .
./clouddrift baseline.json current.json
```

## Example Output

```
Baseline: baseline.json
Current:  current.json

  CLOUDDRIFT  (2 findings)
  ────────────────────────────────────────────────────────────────────────────
  SEVERITY     RULE                           ENTITY
  ────────────────────────────────────────────────────────────────────────────
  CRITICAL     NEW_IAM_USER                   User/backdoor-svc
               ↳ New IAM user backdoor-svc created — immediately has admin policy AdministratorAccess

  HIGH         TRUST_POLICY_CHANGED           Role/ProdDeployRole
               ↳ Trust policy on role ProdDeployRole changed — verify who can now call sts:AssumeRole

  ────────────────────────────────────────────────────────────────────────────
  Summary: 1 CRITICAL  1 HIGH
```

## CI/CD Integration

```yaml
# .github/workflows/iam-drift.yml
name: IAM Drift Detection
on:
  schedule:
    - cron: '0 6 * * *'   # daily at 6am
  workflow_dispatch:

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Download baseline
        run: aws s3 cp s3://my-security-bucket/iam-baseline.json baseline.json
      - name: Capture current state
        run: aws iam get-account-authorization-details > current.json
      - name: Detect drift
        run: go run main.go baseline.json current.json
        # Exits 1 on CRITICAL/HIGH — triggers alert
```

## Zero dependencies

stdlib only: `encoding/json`, `fmt`, `os`, `sort`, `strings`

## License

MIT — Eric Fong (github.com/opsec12)
