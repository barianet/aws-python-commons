import boto3
import tempfile
import zipfile
import os
import json
import iam_management
import hashlib
import time
import base64


class LambdaFunction:
    def __init__(self, function_name, prefix=None, region="us-east-1", endpoint_url=None):
        if endpoint_url is not None:
            self.lambda_client = boto3.client('lambda', region_name=region, endpoint_url=endpoint_url)
        else:
            self.lambda_client = boto3.client('lambda', region_name=region)
        self.function_src_dir = None
        self.function_virtualenv_dir = None
        if prefix is not None:
            self.function_name = prefix + function_name
        else:
            self.function_name = function_name
        self.prefix = prefix
        self.config_json = None
        self.src_hash = None

    def get_function_name(self):
        return self.function_name

    def set_lambda_src_dir(self, src_dir):
        assert isinstance(src_dir, str)
        self.function_src_dir = src_dir

    def set_virtualenv_dir(self, virtualenv_dir):
        assert isinstance(virtualenv_dir, str)
        self.function_virtualenv_dir = virtualenv_dir

    def unset_function_src(self):
        self.function_src_dir = None
        self.function_virtualenv_dir = None

    def get_function_zip_binary(self):
        fd, temp_path = tempfile.mkstemp()
        zipfh = zipfile.ZipFile(temp_path, 'w')
        oldcwd = os.getcwd()
        os.chdir(self.function_src_dir)
        try:
            for root, dirs, files in os.walk('.'):
                for f in files:
                    zipfh.write(os.path.join(root, f))
            if self.function_virtualenv_dir is not None:
                os.chdir(self.function_virtualenv_dir)
                for root, dirs, files in os.walk('.'):
                    for f in files:
                        zipfh.write(os.path.join(root, f))
            zipfh.close()
            with open(temp_path, "rb") as zipped_code:
                zip_binary = zipped_code.read()
        finally:
            zipfh.close()
            os.chdir(oldcwd)
            os.close(fd)
            os.remove(temp_path)
        self.src_hash = base64.b64encode(hashlib.sha256(zip_binary).digest())
        return zip_binary

    def get_src_hash(self):
        return self.src_hash

    def get_lambda_function_arn(self, function_name):
        response = self.lambda_client.list_functions()
        function_arn = None
        for function in response['Functions']:
            if function['FunctionName'] == function_name:
                function_arn = function['FunctionArn']
                break
        return function_arn

    def set_config(self, config_json_str):
        assert isinstance(config_json_str, str)
        self.config_json = json.loads(config_json_str)

    def load_config(self, config_json_path):
        with open(config_json_path, 'r') as config_file:
            self.config_json = json.load(config_file)

    def get_config(self):
        if self.config_json is None:
            raise Exception("Function configuration not yet set.")
        config = self.config_json
        if 'Timeout' not in config:
            raise Exception("Timeout key missing from config")
        if 'MemorySize' not in config:
            raise Exception("MemorySize key missing from config")
        config['Runtime'] = 'python2.7'
        config['Publish'] = True
        if 'FunctionName' not in config:
            config['FunctionName'] = self.function_name
        if 'Description' not in config:
            config['Description'] = self.function_name
        if 'Handler' not in config:
            config['Handler'] = 'lambda_function.lambda_handler'
        if 'Role' not in config:
            role_arn = iam_management.IamManagement().get_role_arn(self.function_name)
            if role_arn is None:
                raise Exception("Cannot find IAM role for function. Looking for %s" % self.function_name)
            config['Role'] = role_arn
        return config

    def publish(self):
        config = self.get_config()
        # There is a race condition that if you have just created a role for the function you may get the error,
        # "The role defined for the function cannot be assumed by Lambda".
        # Couldn't find a way to test when it is ready so nasty sleep hack is all we can do!
        time.sleep(5)
        # iam_management.IamManagement().get_role_arn(self.function_name)
        if self.get_lambda_function_arn(self.function_name) is None:
            if self.function_src_dir is None:
                raise Exception("Function source directory needs to be set for a new function")
            response = self.lambda_client.create_function(
                    FunctionName=config['FunctionName'],
                    Runtime=config['Runtime'],
                    Role=config['Role'],
                    Handler=config['Handler'],
                    Code={
                        'ZipFile': self.get_function_zip_binary(),
                    },
                    Description=config['Description'],
                    Timeout=config['Timeout'],
                    MemorySize=config['MemorySize'],
                    Publish=config['Publish']
            )
        else:
            response = self.lambda_client.update_function_configuration(
                    FunctionName=config['FunctionName'],
                    Role=config['Role'],
                    Handler=config['Handler'],
                    Description=config['Description'],
                    Timeout=config['Timeout'],
                    MemorySize=config['MemorySize'],
            )
            # If function_src_dir is None then assume this is just a config update to the existing function
            if self.function_src_dir is not None:
                update = self.lambda_client.update_function_code(FunctionName=config['FunctionName'],
                                                                 ZipFile=self.get_function_zip_binary())
                response = self.lambda_client.publish_version(FunctionName=config['FunctionName'],
                                                              CodeSha256=update['CodeSha256'])
        if response['CodeSha256'] != self.src_hash:
            raise Exception("Uploaded function source hash (%s) does not match expected hash (%s)" % (
                response['CodeSha256'], self.src_hash))
        return dict(FunctonArn=response['FunctionArn'], Version=response['Version'], CodeSha256=response['CodeSha256'])

    def delete(self, delete_associated_iam=False):
        self.lambda_client.delete_function(self.function_name)
        if delete_associated_iam is True:
            iam_management.IamManagement().delete_role_and_associated_policies(self.function_name)
