"""Path B - custom threat detector (replaces GuardDuty, which is unavailable on the Free plan).

Trigger : EventBridge rule `threat-detector` (CloudTrail management events).
Detects :
  * StopLogging / DeleteTrail / UpdateTrail  - someone tampers with the audit trail
        -> StopLogging is self-healed (logging is switched back on) and alerted
  * AuthorizeSecurityGroupIngress open to 0.0.0.0/0 or ::/0 - alert only
  * ConsoleLogin failures or root logins - alert only (only seen if the sign-in
        happens in this region)
Config  : TOPIC_ARN, TRAIL_NAME, ROLE_NAME (loop guard).
"""
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cloudtrail = boto3.client("cloudtrail")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
TRAIL_NAME = os.environ.get("TRAIL_NAME", "ia2-trail")
ROLE_NAME = os.environ.get("ROLE_NAME", "remediation-role")

WORLD = {"0.0.0.0/0", "::/0"}


def open_to_world(request):
    """Return the (protocol, port range) rules in a security-group request that allow the world."""
    found = []
    for perm in ((request or {}).get("ipPermissions") or {}).get("items", []):
        cidrs = [r.get("cidrIp") for r in (perm.get("ipRanges") or {}).get("items", [])]
        cidrs += [r.get("cidrIpv6") for r in (perm.get("ipv6Ranges") or {}).get("items", [])]
        if WORLD.intersection(cidrs):
            found.append(f"{perm.get('ipProtocol')} {perm.get('fromPort')}-{perm.get('toPort')}")
    return found


def is_our_trail(request):
    name = (request or {}).get("name", "")
    return name == TRAIL_NAME or name.endswith(f"/{TRAIL_NAME}")


def classify(detail):
    """Return (subject, finding, action_taken) or None if the event is not a threat."""
    name = detail.get("eventName")
    request = detail.get("requestParameters")

    if name in ("StopLogging", "DeleteTrail", "UpdateTrail") and is_our_trail(request):
        if name == "StopLogging":
            cloudtrail.start_logging(Name=TRAIL_NAME)
            logger.info("ACTION=SELF_HEAL CloudTrail logging re-enabled")
            return ("CloudTrail logging was stopped",
                    f"{name} on trail {TRAIL_NAME}", "Logging switched back on automatically.")
        return ("CloudTrail trail tampered with",
                f"{name} on trail {TRAIL_NAME}", "Alert only; manual review required.")

    if name == "AuthorizeSecurityGroupIngress":
        rules = open_to_world(request)
        if rules:
            group = (request or {}).get("groupId", "unknown")
            return ("Security group opened to the internet",
                    f"{group} allows 0.0.0.0/0 on: {', '.join(rules)}",
                    "Alert only; review or revoke the rule.")

    if name == "ConsoleLogin":
        failed = (detail.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
        root = detail.get("userIdentity", {}).get("type") == "Root"
        if failed or root:
            return ("Suspicious console login",
                    "failed login" if failed else "root account login", "Alert only.")
    return None


def lambda_handler(event, context):
    detail = event.get("detail", {})
    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    event_name = detail.get("eventName", "unknown")
    event_time = detail.get("eventTime", event.get("time", "unknown"))
    logger.info("Received event=%s actor=%s time=%s", event_name, actor, event_time)

    # Loop guard: never react to our own actions.
    if f":assumed-role/{ROLE_NAME}/" in actor:
        logger.info("ACTION=SKIP_SELF actor is own execution role, stopping")
        return {"status": "skipped_self"}

    try:
        result = classify(detail)
    except Exception as exc:
        logger.exception("ACTION=FAILED while handling %s", event_name)
        result = ("Threat detected but action FAILED", f"{event_name}: {exc}",
                  "Manual review required.")

    if result is None:
        logger.info("ACTION=IGNORE event is not a threat")
        return {"status": "ignored"}

    subject, finding, action = result
    logger.info("ACTION=ALERT %s | %s", subject, finding)
    body = (f"Finding    : {subject}\n"
            f"Detail     : {finding}\n"
            f"Event name : {event_name}\n"
            f"Actor      : {actor}\n"
            f"Event time : {event_time}\n"
            f"Source IP  : {detail.get('sourceIPAddress', 'unknown')}\n"
            f"Action     : {action}\n")
    try:
        sns.publish(TopicArn=TOPIC_ARN, Subject=f"security alert: {subject}"[:100], Message=body)
    except Exception:
        logger.exception("SNS publish failed")
        return {"status": "alert_failed"}
    return {"status": "alerted"}
