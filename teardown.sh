#!/usr/bin/env bash
# Removes everything created by deploy.sh / test.sh. Safe to re-run (missing items just report errors).
set -uo pipefail
cd "$(dirname "$0")"
source ./config.sh

echo "== EventBridge"
for r in "$RULE_S3" "$RULE_DET"; do
  aws events remove-targets --rule "$r" --ids lambda >/dev/null
  aws events delete-rule --name "$r"
done
echo "== Lambdas and log groups"
for f in "$FN_S3" "$FN_DET" "$FN_KEY"; do
  aws lambda delete-function --function-name "$f"
  aws logs delete-log-group --log-group-name "/aws/lambda/$f"
done
echo "== SNS"
aws sns delete-topic --topic-arn "$TOPIC_ARN"
echo "== CloudTrail"
aws cloudtrail stop-logging --name "$TRAIL"
aws cloudtrail delete-trail --name "$TRAIL"
echo "== Buckets"
for b in "$TEST_BUCKET" "$LOG_BUCKET"; do
  aws s3 rm "s3://$b" --recursive >/dev/null
  aws s3api delete-bucket --bucket "$b"
done
echo "== IAM"
aws iam delete-role-policy --role-name "$ROLE" --policy-name remediation-policy
aws iam delete-role --role-name "$ROLE"
for k in $(aws iam list-access-keys --user-name "$TEST_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null | tr -d '\r'); do
  aws iam delete-access-key --user-name "$TEST_USER" --access-key-id "$k"
done
aws iam delete-user --user-name "$TEST_USER"
echo "== Test security group (if t2 was interrupted)"
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=ia2-test-sg --query 'SecurityGroups[0].GroupId' --output text | tr -d '\r')
[ "$SG" = "None" ] || aws ec2 delete-security-group --group-id "$SG"
echo "== Budget"
aws budgets delete-budget --account-id "$ACCOUNT_ID" --budget-name ia2-budget
echo "Teardown finished. Check the Billing page tomorrow to confirm no charges."
