from unittest import TestCase
from awscommons import account

class contextMock():
    invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:funcName'

class Test_Account(TestCase):
    def test_get_account_id(self):
        context = contextMock
        account_id = account.get_account_id(context)
        self.assertEqual(account_id, '123456789012')
