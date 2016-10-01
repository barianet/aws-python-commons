import boto3
import re
import json
import botocore.exceptions as boto_exceptions
import core


def delete_non_default_policy_versions(policy_arn, iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    logger.info("Deleting non-default policy versions of policy %s" % policy_arn)
    # Delete old policy versions to maintain within the 5 limit
    policy_versions = iam_client.list_policy_versions(
        PolicyArn=policy_arn
    )
    for policy_version in policy_versions['Versions']:
        if not policy_version['IsDefaultVersion']:
            logger.debug("Deleting policy version %s of policy %s" % (policy_version['VersionId'], policy_arn))
            iam_client.delete_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version['VersionId']
            )


def get_policy_statement_by_sid(logger, policy_doc, sid):
    for statement in policy_doc['Statement']:
        if 'Sid' not in statement:
            continue
        if statement['Sid'] == sid:
            logger.debug("Found IAM statement with Sid %s" % sid)
            return statement
    logger.debug("Cloud not find IAM statement with Sid %s")
    return None


def add_policy_array_item(policy_arn, policy_default_version, sid, array_key, item,
                          iam_client=None, logger=None):
    update_policy_array(policy_arn, policy_default_version, sid, array_key, item, True, iam_client=iam_client,
                        logger=logger)


def remove_policy_array_item(policy_arn, policy_default_version, sid, array_key, item,
                             iam_client=None, logger=None):
    update_policy_array(policy_arn, policy_default_version, sid, array_key, item, True, iam_client=iam_client,
                        logger=logger)


def update_policy_array(policy_arn, policy_default_version, sid, array_key, item, to_contain=False,
                        iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    # Delete old policy versions to maintain within the 5 limit
    delete_non_default_policy_versions(logger, policy_arn)
    # Get the current default policy content
    policy_content = iam_client.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=policy_default_version
    )
    policy_doc = policy_content['PolicyVersion']['Document']
    statement = get_policy_statement_by_sid(logger, policy_doc, sid)
    if statement is not None:
        if array_key in statement:
            if not isinstance(statement[array_key], list):
                raise TypeError("Not an array at key %s" % array_key)
            needs_update = False
            if to_contain:
                if item not in statement[array_key]:
                    statement[array_key].append(item)
                    needs_update = True
                else:
                    logger.debug("Item %s already defined in policy statement %s array key %s. Nothing to do." % (
                        item, sid, array_key))
                    return policy_default_version
            else:
                if item in statement[array_key]:
                    statement[array_key].remove(item)
                    needs_update = True
                else:
                    logger.debug("Item %s not found in policy statement %s array key %s. Nothing to do." % (
                        item, sid, array_key))
                    return policy_default_version
            if needs_update:
                logger.debug("Updating policy at statement id %s array key %s" % (sid, array_key))
                logger.debug("New policy document: %s" % json.dumps(policy_doc))
                update = iam_client.create_policy_version(
                    PolicyArn=policy_arn,
                    PolicyDocument=json.dumps(policy_doc),
                    SetAsDefault=True
                )
                logger.info(
                    "IAM policy updated, new policy version: %s" % update['PolicyVersion']['VersionId'])
                return update['PolicyVersion']['VersionId']
        else:
            logger.error("Array not found in statement %s at key %s" % (sid, array_key))
    else:
        logger.error(
            "Statement with Sid %s not found in policy %s version %s" % (sid, policy_arn, policy_default_version))
    return None


def find_policy_by_name_regex(policy_name_regex, iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    matching_policies = []
    policies = iam_client.list_policies(
        Scope='Local',
        OnlyAttached=False,
    )
    if policies is not None:
        policy_name_regex = re.compile(policy_name_regex)
        for policy in policies['Policies']:
            if policy_name_regex.match(policy['PolicyName']):
                policy_dict = {
                    'policy_name': policy['PolicyName'],
                    'arn': policy['Arn'],
                    'default_version': policy['DefaultVersionId']
                }
                matching_policies.append(policy_dict)
    if len(matching_policies) < 1:
        logger.debug("No policies found whose name matched regex: %s" % policy_name_regex)
        return None


def get_policy_arn_default_version(policy_name, iam_client=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    policies = iam_client.list_policies(
        Scope='Local',
        OnlyAttached=False,
    )
    ret_dict = {
        'policy_name': None,
        'arn': None,
        'default_version': None
    }
    if policies is not None:
        for policy in policies['Policies']:
            if policy['PolicyName'] == policy_name:
                ret_dict['policy_name'] = policy['PolicyName']
                ret_dict['arn'] = policy['Arn']
                ret_dict['default_version'] = policy['DefaultVersionId']
                break
    return ret_dict


def get_role_arn(role_name, iam_client=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    try:
        response = iam_client.get_role(
            RoleName=role_name
        )
        return response['Role']['Arn']
    except boto_exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return None
        else:
            raise Exception("Unexpected error getting role arn: %s" % e)


def get_role_names_policy_attached_to(policy_name, iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    policy = get_policy_arn_default_version(policy_name, iam_client)
    if policy['arn'] is not None:
        attached_to_roles = []
        response = iam_client.list_roles()
        for role in response['Roles']:
            role_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])
            if any(d['PolicyName'] == policy['policy_name'] for d in role_policies['AttachedPolicies']):
                attached_to_roles.append(role['RoleName'])
        if len(attached_to_roles) < 1:
            logger.debug("Policy %s is not attached to any roles" % policy_name)
            return None
        else:
            return attached_to_roles
    else:
        logger.debug("No policy with name % found" % policy_name)
        return None


def delete_all_versions_of_policy(policy_name, iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    logger.info("Completely deleting poilcy %s and all its versions" % policy_name)
    policy = get_policy_arn_default_version(policy_name, iam_client)
    if policy['arn'] is not None:
        attached_to_roles = get_role_names_policy_attached_to(policy_name, iam_client)
        if attached_to_roles is not None:
            for role_name in attached_to_roles:
                logger.debug("Detatching policy %s from role %s" % (policy_name, role_name))
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['arn'])
        # Remove old versions
        response = iam_client.list_policy_versions(PolicyArn=policy['arn'])
        for version in response['Versions']:
            if version['IsDefaultVersion'] is not True:
                # TODO error handling needed around this call
                logger.debug("Deleting version %s of policy %s" % (version['VersionId'], policy_name))
                iam_client.delete_policy_version(
                    PolicyArn=policy['arn'],
                    VersionId=version['VersionId'])
        # Delete policy as should now only have one version
        logger.debug("Deleting policy %s now all its versions have been deleted" % policy_name)
        iam_client.delete_policy(PolicyArn=policy['arn'])
    else:
        error_response = {"Error": {
            "Code": "404",
            "Message": "No policy with name %s found" % policy_name
        }
        }
        raise boto_exceptions.ClientError(error_response, "delete_all_versions_of_policy")


def delete_role_and_attached_policies(role_name, force=False, iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    logger.info("Deleting role %s and all its attached polices" % role_name)
    response = iam_client.list_attached_role_policies(RoleName=role_name)
    for attachment in response['AttachedPolicies']:
        policy = iam_client.get_policy(PolicyArn=attachment['PolicyArn'])
        # Should not delete the policy if it is attached to something else unless force is set to true.
        if policy['Policy']['AttachmentCount'] <= 1 or force is True:
            logger.info("Deleting policy %s and all its versions. It is either only attached to role %s or the force options has been set" % (policy['Policy']['PolicyName'], role_name))
            delete_all_versions_of_policy(policy['Policy']['PolicyName'], iam_client)
    response = iam_client.list_role_policies(RoleName=role_name)
    for inline_policy in response['PolicyName']:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=inline_policy)
    iam_client.delete_role(RoleName=role_name)


def roleback_policy(policy_name, iam_client=None, logger=None):
    if iam_client is None:
        iam_client = boto3.client('iam')
    if logger is None:
        logger = core.set_logger()
    policy = get_policy_arn_default_version(policy_name)
    if policy is not None:
        arn = policy['arn']
    else:
        error_response = {"Error": {
            "Code": "404",
            "Message": "No policy with name %s found" % policy_name
        }}
        raise boto_exceptions.ClientError(error_response, "roleback_policy")
    response = iam_client.list_policy_versions(PolicyArn=arn)
    non_default_versions = [version for version in response['Versions'] if version['IsDefaultVersion'] is not True]
    non_default_versions_sorted = sorted(non_default_versions, key=lambda v: v['VersionId'], reverse=True)
    newest_non_default_version_id = non_default_versions_sorted[0]['VersionId']
    logger.info("Rolling back policy %s to newest previous version %s" % (policy_name, newest_non_default_version_id))
    iam_client.set_default_policy_version(
        PolicyArn=arn,
        VersionId=newest_non_default_version_id)
