from unittest import TestCase
from awscommons import lambda_management
import uuid
import boto3


def setUpModule():
    test_uuid = uuid.uuid1()
    global function_name
    function_name = "unit-test-" + str(test_uuid)
    global lambda_mgmt
    lambda_mgmt = lambda_management.LambdaFunction(function_name, prefix="guardrails-")
    global actual_function_name
    actual_function_name = lambda_mgmt.get_function_name()
    global lambda_client
    lambda_client = boto3.client('lambda')

    global iam_client
    iam_client = boto3.client('iam')
    with open('resources/valid_iam_role_trust_policy.json', 'r') as policy_file:
        valid_iam_policy_str = policy_file.read().replace('\n', '')
    iam_client.create_role(
            RoleName=actual_function_name,
            AssumeRolePolicyDocument=valid_iam_policy_str
    )
    with open('resources/lambda_basic_exec_policy.json', 'r') as policy_file:
        policy_str = policy_file.read().replace('\n', '')
    iam_client.put_role_policy(
            RoleName=actual_function_name,
            PolicyName=actual_function_name,
            PolicyDocument=policy_str
    )


def tearDownModule():
    iam_client.delete_role_policy(
            RoleName=actual_function_name,
            PolicyName=actual_function_name
    )
    iam_client.delete_role(
            RoleName=actual_function_name
    )


class TestLambdaManagement(TestCase):
    def test_01_set_config(self):
        with open("resources/lambda_config_minimal.json", 'r') as policy_file:
            json_str = policy_file.read().replace('\n', '')
        lambda_mgmt.set_config(json_str)
        self.assertIsInstance(lambda_mgmt.config_json, dict, msg="Lambda config not loaded as a dictionary")

    def test_02_load_config(self):
        lambda_mgmt.load_config("resources/lambda_config_minimal.json")
        self.assertIsInstance(lambda_mgmt.config_json, dict, msg="Lambda config not loaded as a dictionary")

    def test_03_get_config(self):
        config = lambda_mgmt.get_config()
        self.assertIsInstance(config, dict)
        self.assertEqual(config['Runtime'], 'python2.7')
        self.assertEqual(config['Handler'], 'lambda_function.lambda_handler')
        self.assertIsInstance(config['Role'], str)

    def test_04_lambda_function_publish(self):
        lambda_mgmt.set_lambda_src_dir("resources/test_lambda_function")
        response = lambda_mgmt.publish()
        self.assertEqual(response['Version'], '1',
                         msg=u"Incorrect lambda function code version for a new function. Expected: v1 Actual: {0:s}".format(
                                 response['Version']))
        # Test update but with identical source
        lambda_mgmt.set_lambda_src_dir("resources/test_lambda_function")
        response = lambda_mgmt.publish()
        self.assertEqual(response['Version'], '1',
                         msg=u"Incorrect lambda function code version for a new function. Expected: $LATEST Actual: {0:s}".format(
                                 response['Version']))
        # Test update
        lambda_mgmt.set_lambda_src_dir("resources/test_lambda_function2")
        response = lambda_mgmt.publish()
        self.assertEqual(response['Version'], '2',
                         msg=u"Incorrect lambda function code version for a new function. Expected: $LATEST Actual: {0:s}".format(
                                 response['Version']))
        # Test config update only
        lambda_mgmt.unset_function_src()
        response = lambda_mgmt.publish()
        self.assertEqual(response['Version'], '$LATEST',
                         msg=u"Incorrect lambda function code version for a new function. Expected: $LATEST Actual: {0:s}".format(
                                 response['Version']))
        # Clean up
        lambda_client.delete_function(FunctionName=actual_function_name)
