"""Local unit tests (boto3 mocked, no AWS needed). Run from the project root:
    python tests/test_lambdas.py
"""
import importlib
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
os.environ.update(TOPIC_ARN="arn:aws:sns:ap-southeast-2:111:t", ROLE_NAME="remediation-role",
                  BUCKET_PREFIX="ia2-test-bucket-", ALLOWED_USER="ia2-test-user",
                  TRAIL_NAME="ia2-trail")

USER = "arn:aws:iam::1:user/alice"
OWN_ROLE = "arn:aws:sts::1:assumed-role/remediation-role/fn"


def load(name):
    """Import a Lambda module with boto3 replaced by mocks."""
    fake = types.SimpleNamespace(client=lambda *_a, **_k: mock.MagicMock())
    with mock.patch.dict(sys.modules, {"boto3": fake}):
        sys.modules.pop(name, None)
        return importlib.import_module(name)


def s3_event(arn, bucket="ia2-test-bucket-g1"):
    return {"detail": {"eventName": "DeleteBucketPublicAccessBlock", "eventTime": "t",
                       "userIdentity": {"arn": arn}, "requestParameters": {"bucketName": bucket}}}


class S3RemediationTests(unittest.TestCase):
    def setUp(self):
        self.m = load("s3_auto_remediate")

    def test_remediates_user_change(self):
        self.assertEqual(self.m.lambda_handler(s3_event(USER), None)["status"], "remediated")
        self.m.s3.put_public_access_block.assert_called_once()
        self.m.sns.publish.assert_called_once()

    def test_loop_guard(self):
        self.assertEqual(self.m.lambda_handler(s3_event(OWN_ROLE), None)["status"], "skipped_self")
        self.m.s3.put_public_access_block.assert_not_called()

    def test_out_of_scope_bucket(self):
        self.assertEqual(self.m.lambda_handler(s3_event(USER, "other"), None)["status"], "out_of_scope")

    def test_failure_is_reported(self):
        self.m.s3.put_public_access_block.side_effect = RuntimeError("denied")
        self.assertEqual(self.m.lambda_handler(s3_event(USER), None)["status"], "failed")
        self.m.sns.publish.assert_called_once()


class ThreatDetectorTests(unittest.TestCase):
    def setUp(self):
        self.m = load("threat_detector")

    @staticmethod
    def ev(name, request=None, arn=USER, **extra):
        return {"detail": {"eventName": name, "requestParameters": request,
                           "userIdentity": {"arn": arn}, **extra}}

    def test_stop_logging_is_healed_and_alerted(self):
        r = self.m.lambda_handler(self.ev("StopLogging", {"name": "ia2-trail"}), None)
        self.assertEqual(r["status"], "alerted")
        self.m.cloudtrail.start_logging.assert_called_once_with(Name="ia2-trail")

    def test_other_trail_ignored(self):
        r = self.m.lambda_handler(self.ev("StopLogging", {"name": "someone-elses"}), None)
        self.assertEqual(r["status"], "ignored")
        self.m.cloudtrail.start_logging.assert_not_called()

    def test_delete_trail_alert_only(self):
        r = self.m.lambda_handler(self.ev("DeleteTrail", {"name": "ia2-trail"}), None)
        self.assertEqual(r["status"], "alerted")
        self.m.cloudtrail.start_logging.assert_not_called()

    def test_open_security_group_alerts(self):
        req = {"groupId": "sg-1", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
             "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
        self.assertEqual(self.m.lambda_handler(self.ev("AuthorizeSecurityGroupIngress", req), None)["status"], "alerted")

    def test_private_security_group_ignored(self):
        req = {"groupId": "sg-1", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
             "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}}
        self.assertEqual(self.m.lambda_handler(self.ev("AuthorizeSecurityGroupIngress", req), None)["status"], "ignored")

    def test_failed_console_login_alerts(self):
        r = self.m.lambda_handler(self.ev("ConsoleLogin", responseElements={"ConsoleLogin": "Failure"}), None)
        self.assertEqual(r["status"], "alerted")

    def test_loop_guard(self):
        r = self.m.lambda_handler(self.ev("StopLogging", {"name": "ia2-trail"}, arn=OWN_ROLE), None)
        self.assertEqual(r["status"], "skipped_self")


class KeyDisableTests(unittest.TestCase):
    def setUp(self):
        self.m = load("iam_key_disable")

    def test_disables_only_active_keys(self):
        self.m.iam.list_access_keys.return_value = {"AccessKeyMetadata": [
            {"AccessKeyId": "K1", "Status": "Active"}, {"AccessKeyId": "K2", "Status": "Inactive"}]}
        self.assertEqual(self.m.lambda_handler({"user": "ia2-test-user"}, None)["keys"], ["K1"])

    def test_refuses_other_users(self):
        self.assertEqual(self.m.lambda_handler({"user": "bob"}, None)["status"], "refused")


if __name__ == "__main__":
    unittest.main()
