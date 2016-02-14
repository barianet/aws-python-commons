import boto3
import json
import botocore.exceptions as boto_exceptions

class IamPublish:

    def __init__(self, region="us-east-1", endpoint_url=None):
        if endpoint_url is not None:
            self.iam = boto3.client('iam', region_name=region, endpoint_url=endpoint_url)
        else:
            self.iam = boto3.client('iam', region_name=region)
        self.policy_json = None
        self.policy_arn = None
        self.role_json = None
        self.role_arn = None

    def set_policy_json(self, policy_json_str):
        assert isinstance(policy_json_str, str)
        json.loads(policy_json_str)
        self.policy_json = policy_json_str

    def load_policy_json(self, policy_json_file):
        with open(policy_json_file, 'r') as policy_file:
            policy_json_str = policy_file.read().replace('\n', '')
        self.set_policy_json(policy_json_str)

    def get_policy_json(self):
        return self.policy_json

    def get_policy_arn(self, policy_name):
        policy_arn = None
        response = self.iam.list_policies(Scope='Local')
        for policy in response['Policies']:
            if policy['PolicyName'] == policy_name:
                policy_arn = policy['Arn']
                self.policy_arn = policy_arn
                break
        return policy_arn

    def publish_policy(self, policy_name):
        if self.policy_json is None:
            raise "Policy JSON not set"
        previous_version = None
        current_version = None
        # Check if policy exists
        policy_arn = self.get_policy_arn(policy_name)
        if policy_arn is not None:
            # Remove old versions
            response = self.iam.list_policy_versions(PolicyArn=policy_arn)
            for version in response['Versions']:
                if version['IsDefaultVersion'] is not True:
                    # TODO error handling needed around this call
                    self.iam.delete_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version['VersionId'])
                else:
                    previous_version = version['VersionId']
            # TODO error handling
            response = self.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=self.policy_json,
                SetAsDefault=True)
            current_version = response['PolicyVersion']['VersionId']
        else:
            response = self.iam.create_policy(
                PolicyName=policy_name,
                Path='/',
                PolicyDocument=self.policy_json,
                Description=policy_name)
            policy_arn = response['Policy']['Arn']
            self.policy_arn = policy_arn
            current_version = response['Policy']['DefaultVersionId']
        return dict(PolicyName=policy_name, Arn=policy_arn, CurrentVersion=current_version,
                    PerviousVersion=previous_version)

    def delete_all_versions_of_policy(self, policy_name):
        arn = self.get_policy_arn(policy_name)
        if arn is not None:
            # Remove old versions
            response = self.iam.list_policy_versions(PolicyArn=arn)
            for version in response['Versions']:
                if version['IsDefaultVersion'] is not True:
                    # TODO error handling needed around this call
                    self.iam.delete_policy_version(
                        PolicyArn=arn,
                        VersionId=version['VersionId'])
            # Delete policy as should now only have one version
            self.iam.delete_policy(PolicyArn=arn)
        else:
            error_response = {"Error": {
                                "Code": "404",
                                "Message": "No policy with name %s found" % policy_name
                                }
                             }
            raise boto_exceptions.ClientError(error_response, "delete_all_versions_of_policy")

    def roleback_policy(self, policy_name):
        arn = self.get_policy_arn(policy_name)
        response = self.iam.list_policy_versions(PolicyArn=arn)
        non_default_versions = [version for version in response['Versions'] if version['IsDefaultVersion'] is not True]
        non_default_versions_sorted = sorted(non_default_versions, key=lambda v: v['VersionId'], reverse=True)
        newest_non_default_version_id = non_default_versions_sorted[0]['VersionId']
        self.iam.set_default_policy_version(
            PolicyArn=arn,
            VersionId=newest_non_default_version_id)

    def set_role_json(self, role_json_str):
        assert isinstance(role_json_str, str)
        json.loads(role_json_str)
        self.role_json = role_json_str

    def load_role_json(self, role_json_file):
        with open(role_json_file, 'r') as role_file:
            role_json_str = role_file.read().replace('\n', '')
        self.set_role_json(role_json_str)

    def get_role_json(self):
        return self.role_json

    def publish_role(self, role_name):
        if self.role_json is None:
            raise "Role JSON not set"
        response = self.iam.list_roles()
        role_arn = None
        for role in response['Roles']:
            if role['RoleName'] == role_name:
                role_arn = role['Arn']
                self.role_arn = role['Arn']
                self.iam.update_assume_role_policy(
                    RoleName=role_name,
                    PolicyDocument=self.role_json)
                break
        if role_arn is None:
            response = self.iam.create_role(RoleName=role_name,
                                            AssumeRolePolicyDocument=self.role_json)
            self.role_arn = response['Role']['Arn']
            role_arn = response['Role']['Arn']
        return role_arn

    def attach_role_policy(self):
        self.iam.attach_role_policy(
                RoleName=self.role_name,
                PolicyArn=self.policy_arn)

