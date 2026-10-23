# Test evidence

Real run on AWS, region `ap-southeast-2`, 2026-10-16 (UTC) / 2026-10-17 (IST, UTC+5:30).
Account ID and key IDs are redacted. The stack was torn down after testing.

## T1 - Public bucket auto-fix: PASS
- Test bucket `ia2-test-bucket-<group>`; Block Public Access removed with `aws s3api delete-public-access-block`.
- CloudTrail event: `DeleteBucketPublicAccessBlock` at **20:06:09Z**.
- Lambda log: `ACTION=REMEDIATE bucket=ia2-test-bucket-<group> block public access re-applied` at **20:06:17.852Z** (about 9 s after the change).
- Poll result: `PASS: Block Public Access re-enabled after 15s`.
- Alert email "auto-remediation: S3 public access re-blocked" received (see `measure.md`).
- First attempt (19:53:08Z) did not trigger: the rule listed `DeletePublicAccessBlock` but CloudTrail records
  `DeleteBucketPublicAccessBlock`. The rule was corrected and the test repeated (see README, Deviations).

## T2 - Threat alert (security group open to the world): PASS
- `test.sh t2` created a throwaway security group and authorised `tcp/22` from `0.0.0.0/0`, then deleted the group.
- Lambda `threat-detector` log, **20:09:38.228Z**:
  `ACTION=ALERT Security group opened to the internet | sg-0d171dc7da330043b allows 0.0.0.0/0 on: tcp 22-22`
- Alert email "security alert: Security group opened to the internet" received.

## T3 - Loop guard: PASS
`s3-auto-remediate` log group, last 30 minutes:
```
ACTION=REMEDIATE: 2
ACTION=SKIP_SELF: 2
ACTION=FAILED:    0
```
Each change (one restore of the setting while fixing the rule, one T1 run) produced exactly one remediation and one
skipped self-trigger, for example:
```
20:06:17.852Z  ACTION=REMEDIATE bucket=ia2-test-bucket-<group> block public access re-applied
20:06:22.748Z  ACTION=SKIP_SELF actor is own execution role, stopping
```
No repeated runs, so no endless loop.

## T4 - CloudWatch logging evidence: PASS
Execution entries with timestamps exist for both functions (log groups `/aws/lambda/s3-auto-remediate` and
`/aws/lambda/threat-detector`), as quoted in T1-T3 and T7.

## T5 - Least-privilege role: PASS
`remediation-role` has no managed policies and one inline policy with five statements:
| Sid | Action | Resource |
| --- | --- | --- |
| Logs | `logs:CreateLogGroup/CreateLogStream/PutLogEvents` | log groups of the three functions only |
| S3BlockPublicAccess | `s3:PutBucketPublicAccessBlock` | `arn:aws:s3:::ia2-test-bucket-*` |
| PublishAlert | `sns:Publish` | the `security-alerts` topic only |
| TrailSelfHeal | `cloudtrail:StartLogging` | the `ia2-trail` trail only |
| DisableTestUserKey | `iam:ListAccessKeys`, `iam:UpdateAccessKey` | the `ia2-test-user` user only |

## T6 (optional) - IAM key disable: PASS
- Created a throwaway user `ia2-test-user` and key `AKIA...ABMPC` (Active).
- Invoked `iam-key-disable` with `{"user": "ia2-test-user"}`; response `{"status": "disabled", "keys": ["AKIA...ABMPC"]}`.
- `aws iam list-access-keys` afterwards: key status **Inactive**. The Lambda refuses any other user name.

## T7 (extra) - CloudTrail self-heal: PASS
- `aws cloudtrail stop-logging` at **20:09:15Z**.
- Lambda log, **20:09:19.039Z**: `ACTION=SELF_HEAL CloudTrail logging re-enabled`, followed by `ACTION=ALERT CloudTrail logging was stopped | StopLogging on trail ia2-trail`.
- Poll result: `PASS: CloudTrail logging switched back on after 13s`.

## Unit tests (no AWS needed)
`python tests/test_lambdas.py` -> 13 tests, all passing (loop guard, out-of-scope bucket, failure reporting, trail
self-heal, open and private security groups, failed console login, key-disable safety).

## Teardown: verified
After `teardown.sh`, read-only checks found no EventBridge rules, Lambdas, log groups, SNS topics, trails, buckets,
`remediation-role`, `ia2-test-user`, test security group or budget left in the region.
