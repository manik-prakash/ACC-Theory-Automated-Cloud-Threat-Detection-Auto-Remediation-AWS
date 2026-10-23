# Automated Cloud Threat Detection & Auto-Remediation on AWS

Event-driven security pipeline built only from free-tier-friendly services in one region (`ap-southeast-2`).
GuardDuty is not available on this account's Free plan, so threat detection is a custom Lambda over CloudTrail events.

## Architecture

```
                         ┌──────────────┐
 any API call ─────────► │  CloudTrail  │──► S3 log bucket (audit record)
                         └──────┬───────┘
                                │ management events
                         ┌──────▼───────┐
                         │ EventBridge  │
                         └───┬──────┬───┘
      rule: s3-public-access-change │ rule: threat-detector
      (S3 public-access API calls)  │ (trail tampering, open security group, bad login)
                ┌───────────────────┘      └────────────────────┐
        ┌───────▼────────┐                             ┌────────▼───────┐
        │ s3-auto-       │                             │ threat-        │
        │ remediate      │                             │ detector       │
        │ re-block bucket│                             │ alert + heal   │
        └───────┬────────┘                             │ CloudTrail     │
                │                                      └────────┬───────┘
                └──────────────► SNS topic ◄───────────────────┘
                                 security-alerts ──► admin email
 Lambda logs ──► CloudWatch Logs          iam-key-disable (optional, manual invoke)
```

| Path | Detects | Response |
| --- | --- | --- |
| A | Block Public Access removed, public bucket policy/ACL | Re-apply all four settings, email |
| B | `StopLogging` on our trail | Switch logging back on, email |
| B | `DeleteTrail`/`UpdateTrail`, security group open to `0.0.0.0/0`, failed or root console login | Email alert |
| Optional | - | `iam-key-disable` deactivates a throwaway test user's access key |

Safety features: a **loop guard** in both Lambdas (they ignore events caused by their own role), a **least-privilege role**
(`policies/remediation-policy.json`), configuration only through environment variables, and a bucket-name prefix
limit on remediation.

## Run
Prerequisites: AWS CLI v2 signed in as an IAM admin (not root), Git Bash, Python 3.

```bash
export GROUP=<yourgroup>  EMAIL=<admin@email>      # lowercase group name
./deploy.sh        # budget alert, buckets, CloudTrail, SNS, IAM role, 3 Lambdas, 2 rules
# confirm the SNS subscription email, then wait ~5 minutes for CloudTrail
./test.sh t1       # public bucket auto-fix (record times in measure.md)
./test.sh t2       # security group opened to the internet -> alert
./test.sh t3       # loop-guard check
./test.sh t4       # CloudWatch evidence
./test.sh t5       # IAM role permissions
./test.sh t6       # optional IAM key disable
./test.sh t7       # CloudTrail self-heal
./teardown.sh      # delete everything, check Billing next day
```
Unit tests without AWS: `python tests/test_lambdas.py`

## Layout
- `lambda/` - `s3_auto_remediate.py`, `threat_detector.py`, `iam_key_disable.py`
- `policies/` - IAM, SNS, bucket policies and EventBridge patterns (placeholders filled by `config.sh`)
- `deploy.sh`, `test.sh`, `teardown.sh`, `config.sh`; `measure.md` for the response-time table

## Known limits
- IAM and some console-sign-in events are global and only logged in us-east-1, which this account's organization blocks, so IAM-based detection is not included.
- Detection depends on CloudTrail delivery, so alerts arrive about a minute after the action.
