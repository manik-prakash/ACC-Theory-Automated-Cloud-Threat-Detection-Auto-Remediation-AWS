"""Path A - auto-remediate S3 public-access changes.

Trigger : EventBridge rule `s3-public-access-change` (CloudTrail S3 API calls).
Action  : re-apply all four S3 Block Public Access settings, then alert via SNS.
Config  : TOPIC_ARN (SNS topic), ROLE_NAME (own role, for the loop guard),
          BUCKET_PREFIX (only buckets with this prefix are touched).
"""
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
ROLE_NAME = os.environ.get("ROLE_NAME", "remediation-role")
BUCKET_PREFIX = os.environ.get("BUCKET_PREFIX", "")

BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def lambda_handler(event, context):
    # 1. Read the facts from the CloudTrail record carried by EventBridge.
    detail = event.get("detail", {})
    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    event_name = detail.get("eventName", "unknown")
    event_time = detail.get("eventTime", event.get("time", "unknown"))
    bucket = (detail.get("requestParameters") or {}).get("bucketName")

    logger.info("Received event=%s bucket=%s actor=%s time=%s",
                event_name, bucket, actor, event_time)

    # 2. Loop guard: our own fix is itself an S3 API call that matches the rule.
    if f":assumed-role/{ROLE_NAME}/" in actor:
        logger.info("ACTION=SKIP_SELF actor is own execution role, stopping")
        return {"status": "skipped_self"}

    if not bucket:
        logger.error("ACTION=SKIP_NO_BUCKET no bucketName in event")
        return {"status": "no_bucket"}

    if BUCKET_PREFIX and not bucket.startswith(BUCKET_PREFIX):
        logger.info("ACTION=SKIP_OUT_OF_SCOPE bucket %s outside prefix", bucket)
        return {"status": "out_of_scope"}

    # 3. Remediate, 4. alert. A failure is logged and reported, never silent.
    try:
        s3.put_public_access_block(Bucket=bucket,
                                   PublicAccessBlockConfiguration=BLOCK_ALL)
        logger.info("ACTION=REMEDIATE bucket=%s block public access re-applied", bucket)
        subject = "auto-remediation: S3 public access re-blocked"
        action = "All four Block Public Access settings re-applied."
        status = "remediated"
    except Exception as exc:
        logger.exception("ACTION=FAILED remediation failed for bucket=%s", bucket)
        subject = "auto-remediation FAILED: S3 bucket may be public"
        action = f"Remediation failed ({exc}). Manual review required."
        status = "failed"

    body = (f"Event name : {event_name}\n"
            f"Bucket     : {bucket}\n"
            f"Changed by : {actor}\n"
            f"Event time : {event_time}\n"
            f"Action     : {action}\n")
    try:
        sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=body)
    except Exception:
        logger.exception("SNS publish failed")
        status += "_alert_failed"
    return {"status": status}
