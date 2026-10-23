"""Optional - deactivate the access keys of ONE throwaway test IAM user.

Trigger : manual invoke with {"user": "<name>"} (see test.sh t6).
Safety  : refuses any user other than ALLOWED_USER; the IAM role can only touch that user.
Config  : TOPIC_ARN, ALLOWED_USER.
"""
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
ALLOWED_USER = os.environ.get("ALLOWED_USER", "")


def lambda_handler(event, context):
    user = event.get("user") or ALLOWED_USER
    if not user:
        raise ValueError("no user supplied")
    if ALLOWED_USER and user != ALLOWED_USER:
        logger.error("ACTION=REFUSED user %s is not the allowed test user", user)
        return {"status": "refused"}

    disabled = []
    try:
        for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            if key["Status"] == "Active":
                iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"],
                                      Status="Inactive")
                disabled.append(key["AccessKeyId"])
        logger.info("ACTION=KEY_DISABLED user=%s keys=%s", user, disabled)
        subject = "auto-remediation: IAM access key deactivated"
        body = f"User: {user}\nKeys set Inactive: {', '.join(disabled) or 'none (no active keys)'}\n"
        status = "disabled"
    except Exception as exc:
        logger.exception("ACTION=FAILED could not disable keys for %s", user)
        subject = "auto-remediation FAILED: IAM key not deactivated"
        body = f"User: {user}\nError: {exc}\n"
        status = "failed"

    try:
        sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=body)
    except Exception:
        logger.exception("SNS publish failed")
    return {"status": status, "keys": disabled}
