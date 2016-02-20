from unittest import TestCase
from awscommons import iam_management
import json
import uuid
import boto3
import botocore.exceptions

def setUpModule():
    global iam_mgmt
    iam_mgmt = iam_management.IamManagement()
    global iam_client
    iam_client = boto3.client('iam')
    global valid_iam_policy_str
    valid_iam_policy_str = """{"Version": "2012-10-17","Statement": [{"Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream"], "Resource": "arn:aws:logs:*:*:*"},
        {"Effect": "Allow", "Action": [ "ec2:DescribeVolumes", "ec2:DescribeSnapshots" ], "Resource": "*" }]}"""
    test_uuid = uuid.uuid1()
    global test_policy_name
    test_policy_name = "unit-test-" + str(test_uuid)
    response = iam_client.create_policy(
            PolicyName=test_policy_name,
            Path='/',
            PolicyDocument=valid_iam_policy_str,
            Description=test_policy_name)
    global test_policy_arn
    test_policy_arn = response['Policy']['Arn']
    with open('resources/valid_iam_role_trust_policy.json', 'r') as policy_file:
            valid_iam_policy_str = policy_file.read().replace('\n', '')
    global test_role_name
    test_role_name = test_policy_name
    iam_client.create_role(
            RoleName=test_role_name,
            AssumeRolePolicyDocument=valid_iam_policy_str
    )

def tearDownModule():
    iam_client.delete_role(RoleName=test_role_name)



class TestIamManagement(TestCase):

    def test_01_get_policy_arn(self):
        arn = iam_mgmt.get_policy_arn(test_policy_name)
        self.assertEqual(test_policy_arn, arn,
                         msg="Discovered arn not correct. Discovered: %s Expected: %s" % (arn, test_policy_arn))

    def test_02_set_policy_json(self):
        iam_mgmt.set_policy_json(valid_iam_policy_str)
        policy = json.loads(iam_mgmt.get_policy_json())
        self.assertIsInstance(policy, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(policy))
        with self.assertRaises(AssertionError):
            iam_mgmt.set_policy_json(1)
        with self.assertRaises(ValueError):
            iam_mgmt.set_policy_json("This is not a JSON string")

    def test_03_load_policy_json(self):
        iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        policy = json.loads(iam_mgmt.get_policy_json())
        self.assertIsInstance(policy, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(policy))

    def test_04_new_publish_policy(self):
        iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        policy_name = "unit-test" + str(uuid.uuid1())
        policy_details = iam_mgmt.publish_policy(policy_name)
        iam_client.delete_policy(PolicyArn=policy_details['Arn'])
        self.assertIsInstance(policy_details, dict,
                              msg="Publishing a new policy did not return dictionary of details")
        self.assertEqual(policy_details['CurrentVersion'], "v1",
                         msg="New policy publish did not create with version being 1 value is %s" % policy_details[
                             'CurrentVersion'])

    def test_05_update_publish_policy(self):
        iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        # Update policy
        policy_details = iam_mgmt.publish_policy(test_policy_name)
        self.assertEqual(policy_details['CurrentVersion'], "v2",
                         msg="New policy publish did not create with version being 1 value is %s" % policy_details[
                             'CurrentVersion'])
        iam_mgmt.publish_policy(test_policy_name)
        response = iam_client.list_policy_versions(PolicyArn=test_policy_arn)
        self.assertEqual(len(response['Versions']), 2,
                         msg="Publish should only maintain two versions %i present; current default and one previous" % len(
                                 response['Versions']))

    def test_06_roleback_policy(self):
        response = iam_client.list_policy_versions(PolicyArn=test_policy_arn)
        current_default_version = None
        rollback_version = None
        for version in response['Versions']:
            if version['IsDefaultVersion'] is True:
                current_default_version = version['VersionId']
            else:
                rollback_version = version['VersionId']
        iam_mgmt.roleback_policy(test_policy_name)
        response = iam_client.list_policy_versions(PolicyArn=test_policy_arn)
        for version in response['Versions']:
            if version['IsDefaultVersion'] is True:
                self.assertEqual(version['VersionId'], rollback_version,
                                 msg="Rollback failed. Default version incorrect. Expected: %s Actual: %s" % (
                                 rollback_version, version['VersionId']))
            else:
                self.assertEqual(version['VersionId'], current_default_version,
                                 msg="Rollback failed. Non-Default version incorrect. Expected: %s Actual: %s" % (
                                 current_default_version, version['VersionId']))

    def test_07_delete_all_versions_of_policy(self):
        iam_mgmt.delete_all_versions_of_policy(test_policy_name)
        # Test policy has gone
        with self.assertRaises(botocore.exceptions.ClientError):
            iam_client.list_policy_versions(PolicyArn=test_policy_arn)

    def test_08_set_role_json(self):
        iam_mgmt.set_role_json(valid_iam_policy_str)
        role = json.loads(iam_mgmt.get_role_json())
        self.assertIsInstance(role, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(role))
        with self.assertRaises(AssertionError):
            iam_mgmt.set_role_json(1)
        with self.assertRaises(ValueError):
            iam_mgmt.set_role_json("This is not a JSON string")

    def test_09_load_role_json(self):
        iam_mgmt.load_role_json("resources/valid_iam_role_trust_policy.json")
        role = json.loads(iam_mgmt.get_role_json())
        self.assertIsInstance(role, dict,
                              msg="Policy JSON not loaded. Returned type is %s and not dictionary." % type(role))

    def test_10_new_publish_role(self):
        iam_mgmt.load_role_json("resources/valid_iam_role_trust_policy.json")
        role_name = "unit-test" + str(uuid.uuid1())
        try:
            response = iam_mgmt.publish_role(role_name)
            role_arn = response['Arn']
            self.assertIsInstance(role_arn, str,
                                  msg="Publishing a new role did not return arn string")
            response = iam_client.get_role(RoleName=role_name)
            self.assertEqual(role_arn, response['Role']['Arn'],
                             msg="Role arn does not match. Expect: %s Actual: %s" % (role_arn, response['Role']['Arn']))
        finally:
            # Clean up after test
            iam_client.delete_role(RoleName=role_name)

    def test_11_update_publish_role(self):
        iam_mgmt.load_role_json("resources/valid_iam_role_trust_policy.json")
        role_name = "unit-test" + str(uuid.uuid1())
        # Update role
        try:
            response = iam_mgmt.publish_role(role_name)
            role_arn = response['Arn']
            self.assertIsInstance(role_arn, str,
                                  msg="Publishing a new role did not return arn string")
            response = iam_mgmt.publish_role(role_name)
            role_arn_2 = response['Arn']
            self.assertIsInstance(role_arn, str,
                                  msg="Publishing a new role did not return arn string")
            self.assertEqual(role_arn, role_arn_2,
                             msg="Role arn does not match when updating. First arn: %s Second arn: %s" % (
                             role_arn, role_arn_2))
        finally:
            # Clean up after test
            iam_client.delete_role(RoleName=role_name)

    def test_12_attach_policy_to_a_role(self):
        iam_mgmt.load_policy_json("resources/valid_iam_policy.json")
        iam_mgmt.load_role_json("resources/valid_iam_role_trust_policy.json")
        policy_name = "unit-test-policy" + str(uuid.uuid1())
        role_name = "unit-test-role" + str(uuid.uuid1())
        policy_details = iam_mgmt.publish_policy(policy_name)
        iam_mgmt.publish_role(role_name)
        iam_mgmt.attach_policy_to_a_role(role_name)
        # Clean up after test
        iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_details['Arn'])
        iam_client.delete_policy(PolicyArn=policy_details['Arn'])
        iam_client.delete_role(RoleName=role_name)

    def test_13_get_role_arn(self):
        iam_mgmt.get_role_arn("doesnotexist")
        role_arn = iam_mgmt.get_role_arn(test_role_name)
        self.assertIsNotNone(role_arn)
