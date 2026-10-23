#!/usr/bin/env bash
# Deploys the whole pipeline in ap-southeast-2.
# Usage (Git Bash, from this folder):  GROUP=abc EMAIL=me@example.com ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh

[ "$EMAIL" != "you@example.com" ] || { echo "Set EMAIL first"; exit 1; }
echo "Account $ACCOUNT_ID, region $AWS_REGION"

echo "== 1. Budget alert (5 USD)"
aws budgets create-budget --account-id "$ACCOUNT_ID" --budget file://policies/budget.json \
  --notifications-with-subscribers "$(render policies/budget-notify.json)" \
  || echo "(budget already exists or not permitted; make sure an alert is set)"

echo "== 2. Buckets (Block Public Access ON)"
for b in "$TEST_BUCKET" "$LOG_BUCKET"; do
  aws s3api create-bucket --bucket "$b" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION" >/dev/null \
    || aws s3api head-bucket --bucket "$b"        # fine if it already exists, else abort
  aws s3api put-public-access-block --bucket "$b" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
done
aws s3api put-bucket-policy --bucket "$LOG_BUCKET" --policy "$(render policies/trail-bucket-policy.json)"

echo "== 3. CloudTrail (management events, read + write)"
aws cloudtrail create-trail --name "$TRAIL" --s3-bucket-name "$LOG_BUCKET" \
  --no-is-multi-region-trail >/dev/null || echo "trail exists"
aws cloudtrail put-event-selectors --trail-name "$TRAIL" \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]' >/dev/null
aws cloudtrail start-logging --name "$TRAIL"

echo "== 4. SNS topic + email subscription"
aws sns create-topic --name "$TOPIC" >/dev/null
aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy \
  --attribute-value "$(render policies/sns-topic-policy.json)"
aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint "$EMAIL" >/dev/null
echo ">>> CONFIRM THE SUBSCRIPTION EMAIL sent to $EMAIL before testing <<<"

echo "== 5. IAM role (least privilege)"
aws iam create-role --role-name "$ROLE" \
  --assume-role-policy-document file://policies/lambda-trust.json >/dev/null || echo "role exists"
aws iam put-role-policy --role-name "$ROLE" --policy-name remediation-policy \
  --policy-document "$(render policies/remediation-policy.json)"
echo "Waiting for role to propagate..."; sleep 15

echo "== 6. Lambda functions"
mkdir -p build
# deploy_fn <name> <source file> <environment>
deploy_fn () {
  python -c "import zipfile;z=zipfile.ZipFile('build/$1.zip','w',zipfile.ZIP_DEFLATED);z.write('lambda/$2','$2');z.close()"
  if aws lambda get-function --function-name "$1" >/dev/null 2>&1; then
    aws lambda update-function-code --function-name "$1" --zip-file "fileb://build/$1.zip" >/dev/null
    aws lambda wait function-updated --function-name "$1"
    aws lambda update-function-configuration --function-name "$1" --environment "$3" >/dev/null
  else
    aws lambda create-function --function-name "$1" --runtime python3.12 --role "$ROLE_ARN" \
      --handler "${2%.py}.lambda_handler" --timeout 30 --zip-file "fileb://build/$1.zip" \
      --environment "$3" >/dev/null
  fi
}
deploy_fn "$FN_S3"  s3_auto_remediate.py "Variables={TOPIC_ARN=$TOPIC_ARN,ROLE_NAME=$ROLE,BUCKET_PREFIX=ia2-test-bucket-}"
deploy_fn "$FN_DET" threat_detector.py   "Variables={TOPIC_ARN=$TOPIC_ARN,ROLE_NAME=$ROLE,TRAIL_NAME=$TRAIL}"
deploy_fn "$FN_KEY" iam_key_disable.py   "Variables={TOPIC_ARN=$TOPIC_ARN,ALLOWED_USER=$TEST_USER}"

echo "== 7. EventBridge rules -> Lambda"
# connect <rule> <pattern file> <function>
connect () {
  aws events put-rule --name "$1" --event-pattern "file://$2" >/dev/null
  aws lambda add-permission --function-name "$3" --statement-id "eb-$1" \
    --action lambda:InvokeFunction --principal events.amazonaws.com \
    --source-arn "arn:aws:events:${AWS_REGION}:${ACCOUNT_ID}:rule/$1" >/dev/null 2>&1 || true
  aws events put-targets --rule "$1" \
    --targets "Id=lambda,Arn=arn:aws:lambda:${AWS_REGION}:${ACCOUNT_ID}:function:$3" >/dev/null
}
connect "$RULE_S3"  policies/rule-s3-pattern.json       "$FN_S3"
connect "$RULE_DET" policies/rule-detector-pattern.json "$FN_DET"

echo "Done. Confirm the SNS email, wait ~5 minutes for CloudTrail, then run ./test.sh"
