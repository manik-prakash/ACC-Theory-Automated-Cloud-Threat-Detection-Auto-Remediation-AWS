# Shared settings. Set GROUP and EMAIL in the environment (or edit the defaults below).
# This account's organization only allows ap-southeast-2, so everything lives there.
export GROUP="${GROUP:-group1}"            # lowercase letters/digits only
export EMAIL="${EMAIL:-you@example.com}"   # admin alert address
export AWS_REGION=ap-southeast-2
export AWS_DEFAULT_REGION=ap-southeast-2
export MSYS_NO_PATHCONV=1                  # stop Git Bash rewriting /aws/... paths

TEST_BUCKET="ia2-test-bucket-${GROUP}"
LOG_BUCKET="ia2-trail-logs-${GROUP}"
TRAIL=ia2-trail
TOPIC=security-alerts
ROLE=remediation-role
FN_S3=s3-auto-remediate
FN_DET=threat-detector
FN_KEY=iam-key-disable
RULE_S3=s3-public-access-change
RULE_DET=threat-detector
TEST_USER=ia2-test-user

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text | tr -d '\r')
TOPIC_ARN="arn:aws:sns:${AWS_REGION}:${ACCOUNT_ID}:${TOPIC}"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE}"

# render <template>: fill ${VAR} placeholders, print the result (used as a CLI argument).
render() {
  sed -e "s|\${ACCOUNT_ID}|${ACCOUNT_ID}|g" -e "s|\${REGION}|${AWS_REGION}|g" \
      -e "s|\${TOPIC_ARN}|${TOPIC_ARN}|g" -e "s|\${LOG_BUCKET}|${LOG_BUCKET}|g" \
      -e "s|\${FN_S3}|${FN_S3}|g" -e "s|\${FN_DET}|${FN_DET}|g" -e "s|\${FN_KEY}|${FN_KEY}|g" \
      -e "s|\${TRAIL}|${TRAIL}|g" -e "s|\${TEST_USER}|${TEST_USER}|g" \
      -e "s|\${EMAIL}|${EMAIL}|g" "$1"
}
