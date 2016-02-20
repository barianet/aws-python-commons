import boto3
import json
import botocore.exceptions as boto_exceptions


class IamManagement:
    def __init__(self, region="us-east-1", endpoint_url=None):
        if endpoint_url is not None:
            self.iam = boto3.client('iam', region_name=region, endpoint_url=endpoint_url)
        else:
            self.iam = boto3.client('iam', region_name=region)
        self.policy_json = None
        self.policy_arn = None
        self.role_json = None

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

    def get_role_arn(self, role_name):
        try:
            response = self.iam.get_role(
                    RoleName=role_name
            )
            return response['Role']['Arn']
        except boto_exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return None
            else:
                raise Exception("Unexpected error: %s" % e)

    def publish_policy(self, policy_name):
        if self.policy_json is None:
            raise Exception("Policy JSON not set")
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

    def find_role_attachements(self, policy_name):
        policy_arn = self.get_policy_arn(policy_name)
        if policy_arn is not None:
            attached_to_roles = []
            response = self.iam.list_roles()
            for role in response['Roles']:
                role_policies = self.iam.list_attached_role_policies(RoleName=role['RoleName'])
                if any(d['PolicyName'] == policy_name for d in role_policies['AttachedPolicies']):
                    attached_to_roles.append(role['RoleName'])
            if len(attached_to_roles) < 1:
                return None
            else:
                return attached_to_roles
        else:
            return None

    def delete_all_versions_of_policy(self, policy_name):
        arn = self.get_policy_arn(policy_name)
        if arn is not None:
            attached_to_roles = self.find_role_attachements(policy_name)
            if attached_to_roles is not None:
                for role_name in attached_to_roles:
                    self.iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
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
                self.iam.update_assume_role_policy(
                        RoleName=role_name,
                        PolicyDocument=self.role_json)
                break
        if role_arn is None:
            response = self.iam.create_role(RoleName=role_name,
                                            AssumeRolePolicyDocument=self.role_json)
            role_arn = response['Role']['Arn']
        return dict(RoleName=role_name, Arn=role_arn)

    def attach_policy_to_a_role(self, role_name):
        self.iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=self.policy_arn)

    def delete_role_and_associated_policies(self, role_name, force=False):
        response = self.iam.list_attached_role_policies(RoleName=role_name)
        for attachements in response['AttachedPolicies']:
            policy = self.iam.get_policy(PolicyArn=attachements['PolicyArn'])
            # Should not delete the policy if it is attached to something else unless force is set to true.
            if policy['Policy']['AttachmentCount'] <= 1 or force is True:
                self.delete_all_versions_of_policy(policy['Policy']['PolicyName'])
        response = self.iam.list_role_policies(RoleName=role_name)
        for inline_policy in response['PolicyName']:
            self.iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy)
        self.iam.delete_role(RoleName=role_name)



