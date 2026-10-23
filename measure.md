# Response-time measurement (test T1)

All times IST (UTC+5:30) on 2026-10-17, region ap-southeast-2. Sources: CloudTrail `eventTime`, CloudWatch log timestamp of `ACTION=REMEDIATE`, and the `test.sh t1` poll.

| Run | Bucket made public (CloudTrail `DeleteBucketPublicAccessBlock`) | Lambda remediated (CloudWatch) | Block Public Access seen restored (poll) | Alert email arrived | Automated response |
| --- | --- | --- | --- | --- | --- |
| 1 | 01:36:09 | 01:36:17.9 | 01:36:25 (+15 s) | _fill from inbox_ | about 9 s to remediate, 15 s to confirm |

Manual response (estimate, not measured): 15-30 minutes to notice, sign in, find the bucket and fix it. Automated handling is therefore roughly 60-120 times faster.

## Notes for the report
- The first attempt (01:23:08) did not trigger anything. The spec named the event `DeletePublicAccessBlock`, but CloudTrail records it as `DeleteBucketPublicAccessBlock`; the EventBridge rule was corrected and the test repeated.
- The loop guard worked: each user change produced one `ACTION=REMEDIATE` and one `ACTION=SKIP_SELF` (the Lambda's own fix), and no further runs.
- Other tests: T7 CloudTrail self-heal restored logging in 13 s; T2 security-group alert logged at 01:39:38 (20:09:38Z).
