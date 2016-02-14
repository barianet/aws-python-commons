from unittest import TestCase
from awscommons import iam_management
import json
import uuid
import boto3
import botocore.exceptions


class TestIamPublish(TestCase):
    iam_mgmt = iam_management.IamPublish()
    iam_client = boto3.client('iam')
    valid_iam_policy_str = """{"Version": "2012-10-17","Statement": [{"Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream"], "Resource": "arn:aws:logs:*:*:*"},
        {"Effect": "Allow", "Action": [ "ec2:DescribeVolumes", "ec2:DescribeSnapshots" ], "Resource": "*" }]}"""
    test_uuid = uuid.uuid1()
    test_policy_name = "unit-test-" + str(test_uuid)
    response = iam_client.create_policy(
            PolicyName=test_policy_name,
            Path='/',
            PolicyDocument=valid_iam_policy_str,
            Description=test_policy_name)
    test_policy_arn = response['Policy']['Arn']

    def test_1_get_policy_arn(self):
        arn = self.iam_mgmt.get_policy_arn(self.test_policy_name)
        self.assertEqual(self.test_policy_arn, arn, msg="Discovered arn not correct. Discovered: %s Expected: %s" % (arn, self.test_policy_arn))

    def test_2_set_policy_json(self):
        self.iam_mgmt.set_policy_json(self.valid_iam_policy_str)
        policy = json.loads(self.iam_mgmt.get_policy_json())
        self.assertIsInstance(policy, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(policy))
        with self.assertRaises(AssertionError):
            self.iam_mgmt.set_policy_json(1)
        with self.assertRaises(ValueError):
            self.iam_mgmt.set_policy_json("This is not a JSON string")

    def test_3_load_policy_json(self):
        self.iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        policy = json.loads(self.iam_mgmt.get_policy_json())
        self.assertIsInstance(policy, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(policy))

    def test_4_set_role_json(self):
        self.iam_mgmt.set_role_json(self.valid_iam_policy_str)
        role = json.loads(self.iam_mgmt.get_role_json())
        self.assertIsInstance(role, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(role))
        with self.assertRaises(AssertionError):
            self.iam_mgmt.set_role_json(1)
        with self.assertRaises(ValueError):
            self.iam_mgmt.set_role_json("This is not a JSON string")

    def test_5_load_role_json(self):
        self.iam_mgmt.load_role_json("resources/valid_iam_role.json")
        role = json.loads(self.iam_mgmt.get_role_json())
        self.assertIsInstance(role, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(role))

    def test_6_new_publish_policy(self):
        self.iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        policy_name = "unit-test" + str(uuid.uuid1())
        try:
            policy_details = self.iam_mgmt.publish_policy(policy_name)
            self.assertIsInstance(policy_details, dict,
                                  msg="Publishing a new policy did not return dictionary of details")
            self.assertEqual(policy_details['CurrentVersion'], "v1",
                             msg="New policy publish did not create with version being 1 value is %s" % policy_details[
                                 'CurrentVersion'])
        finally:
            # Clean up after test
            self.iam_client.delete_policy(PolicyArn=policy_details['Arn'])

    def test_7_update_publish_policy(self):
        self.iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        # Update policy
        policy_details = self.iam_mgmt.publish_policy(self.test_policy_name)
        self.assertEqual(policy_details['CurrentVersion'], "v2",
                         msg="New policy publish did not create with version being 1 value is %s" % policy_details[
                             'CurrentVersion'])
        self.iam_mgmt.publish_policy(self.test_policy_name)
        response = self.iam_client.list_policy_versions(PolicyArn=self.test_policy_arn)
        self.assertEqual(len(response['Versions']), 2,
                         msg="Publish should only maintain two versions %i present; current default and one previous" % len(
                                 response['Versions']))

    def test_8_roleback_policy(self):
        response = self.iam_client.list_policy_versions(PolicyArn=self.test_policy_arn)
        current_default_version = None
        rollback_version = None
        for version in response['Versions']:
            if version['IsDefaultVersion'] is True:
                current_default_version = version['VersionId']
            else:
                rollback_version = version['VersionId']
        self.iam_mgmt.roleback_policy(self.test_policy_name)
        response = self.iam_client.list_policy_versions(PolicyArn=self.test_policy_arn)
        for version in response['Versions']:
            if version['IsDefaultVersion'] is True:
                self.assertEqual(version['VersionId'], rollback_version,
                                 msg="Rollback failed. Default version incorrect. Expected: %s Actual: %s" %(rollback_version, version['VersionId']))
            else:
                self.assertEqual(version['VersionId'], current_default_version,
                                 msg="Rollback failed. Non-Default version incorrect. Expected: %s Actual: %s" %(current_default_version, version['VersionId']))

    def test_9_delete_all_versions_of_policy(self):
        self.iam_mgmt.delete_all_versions_of_policy(self.test_policy_name)
        # Test policy has gone
        with self.assertRaises(botocore.exceptions.ClientError):
            self.iam_client.list_policy_versions(PolicyArn=self.test_policy_arn)
