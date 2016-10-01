

# Takes the context object provided by the lambda framework
def get_account_id(context):
    return context.invoked_function_arn.split(':')[4]
