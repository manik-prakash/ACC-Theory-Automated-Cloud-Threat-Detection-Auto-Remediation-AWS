#!/usr/bin/env bash
# Usage: ./test.sh t1|t2|t3|t4|t5|t6|t7     (watch your inbox after each test)
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh
LG_S3="/aws/lambda/$FN_S3"
LG_DET="/aws/lambda/$FN_DET"

# wait_for <description> <timeout-seconds> <command...>: poll until the command succeeds.
wait_for () {
  local desc=$1 limit=$2; shift 2
  local start; start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    [ $(( $(date +%s) - start )) -lt "$limit" ] || { echo "FAIL: $desc not seen after ${limit}s"; return 1; }
    echo "  +$(( $(date +%s) - start ))s waiting for: $desc"; sleep 10
  done
  echo "PASS: $desc after $(( $(date +%s) - start ))s"
}
bpa_on () { [ "$(aws s3api get-public-access-block --bucket "$TEST_BUCKET" \
  --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
  --output text | tr -d '\r')" = "$(printf 'True\tTrue\tTrue\tTrue')" ]; }
trail_on () { [ "$(aws cloudtrail get-trail-status --name "$TRAIL" --query IsLogging --output text | tr -d '\r')" = "True" ]; }

case "${1:-}" in
t1)  # Public bucket auto-fix
  echo "Removing Block Public Access on $TEST_BUCKET at $(date -u +%FT%TZ)"
  aws s3api delete-public-access-block --bucket "$TEST_BUCKET"
  wait_for "Block Public Access re-enabled" 600 bpa_on
  echo "Now check the email (bucket, actor, time, action) and note its arrival time." ;;
t2)  # Detector: security group open to the world (alert only)
  VPC=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text | tr -d '\r')
  SG=$(aws ec2 create-security-group --group-name ia2-test-sg --description "ia2 test, safe to delete" \
        --vpc-id "$VPC" --query GroupId --output text | tr -d '\r')
  aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
  echo "Opened $SG to 0.0.0.0/0 on port 22; expect a 'Security group opened to the internet' email."
  echo "Waiting 3 min for the alert before cleaning up..."; sleep 180
  aws ec2 delete-security-group --group-id "$SG" && echo "Test security group deleted" ;;
t3)  # Loop guard: one REMEDIATE per user change, and the self-triggered run is skipped
  SINCE=$(( ($(date +%s) - 1800) * 1000 ))
  for a in ACTION=REMEDIATE ACTION=SKIP_SELF ACTION=FAILED; do
    echo "$a: $(aws logs filter-log-events --log-group-name "$LG_S3" --start-time "$SINCE" \
      --filter-pattern "\"$a\"" --query 'length(events)' --output text | tr -d '\r')"
  done
  echo "Expect REMEDIATE == SKIP_SELF == number of times you ran t1 in the last 30 min." ;;
t4)  # Logging evidence
  aws logs filter-log-events --log-group-name "$LG_S3" --filter-pattern ACTION \
    --query 'events[].[timestamp,message]' --output text
  aws logs filter-log-events --log-group-name "$LG_DET" --filter-pattern ACTION \
    --query 'events[].[timestamp,message]' --output text ;;
t5)  # Least privilege
  aws iam list-attached-role-policies --role-name "$ROLE"
  aws iam get-role-policy --role-name "$ROLE" --policy-name remediation-policy \
    --query PolicyDocument --output json ;;
t6)  # Optional: IAM key disable
  aws iam create-user --user-name "$TEST_USER" >/dev/null 2>&1 || true
  KID=$(aws iam create-access-key --user-name "$TEST_USER" --query AccessKey.AccessKeyId --output text | tr -d '\r')
  echo "Created throwaway key $KID (Active)"
  aws lambda invoke --function-name "$FN_KEY" --cli-binary-format raw-in-base64-out \
    --payload "{\"user\":\"$TEST_USER\"}" build/t6-out.json >/dev/null
  cat build/t6-out.json; echo
  aws iam list-access-keys --user-name "$TEST_USER" --query 'AccessKeyMetadata[].[AccessKeyId,Status]' --output text ;;
t7)  # CloudTrail self-heal
  echo "Stopping trail $TRAIL at $(date -u +%FT%TZ)"
  aws cloudtrail stop-logging --name "$TRAIL"
  wait_for "CloudTrail logging switched back on" 600 trail_on ;;
*) echo "usage: $0 t1|t2|t3|t4|t5|t6|t7"; exit 1 ;;
esac
