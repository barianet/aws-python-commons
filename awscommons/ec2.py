import boto3
import botocore
import core


def delete_ami_and_snapshots(image_id, ec2_client=None, logger=None):
    if ec2_client is None:
        ec2_client = boto3.client('ec2')
    if logger is None:
        logger = core.set_logger()
    decribe_image_response = ec2_client.describe_images(
        DryRun=False,
        Owners=[
            'self'
        ],
        ImageIds=[
            image_id,
        ]
    )
    delete_ami_and_snapshots_from_describe_image_response(decribe_image_response, ec2_client, logger)


def delete_ami_and_snapshots_from_describe_image_response(decribe_image_response, ec2_client=None, logger=None):
    if ec2_client is None:
        ec2_client = boto3.client('ec2')
    if logger is None:
        logger = core.set_logger()
    if 'Images' in decribe_image_response:
        if len(decribe_image_response['Images']) > 0:
            for image_json in decribe_image_response['Images']:
                try:
                    logger.info("Deregsitering image %s" % image_json['ImageId'])
                    ec2_client.deregister_image(
                        DryRun=False,
                        ImageId=image_json['ImageId']
                    )
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'InvalidAMIID.Unavailable':
                        logger.info("AMI %s no longer present" % image_json['ImageId'])
                    else:
                        raise Exception("Unexpected error: %s" % e)
                for block_device_mapping in image_json['BlockDeviceMappings']:
                    logger.info(
                        "Removing associated block device snapshot %s" % block_device_mapping['Ebs']['SnapshotId'])
                    ec2_client.delete_snapshot(
                        DryRun=False,
                        SnapshotId=block_device_mapping['Ebs']['SnapshotId']
                    )
        else:
            logger.warn("Could not find image(s) to remove")
    else:
        logger.warn("Could not find image(s) to remove")