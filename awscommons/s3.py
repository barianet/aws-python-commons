import boto3
import botocore


def get_s3_object_metadata_value(bucket, object, metadata_key, s3_client=None):
    if s3_client is None:
        s3_client = boto3.client('s3')
    headers = s3_client.head_object(
        Bucket=bucket,
        Key=object,
    )
    if metadata_key.startswith('x-amz-meta-'):
        metadata_key = metadata_key[len('x-amz-meta-'):]
    if metadata_key in headers['Metadata']:
        return headers['Metadata'][metadata_key]
    return None
