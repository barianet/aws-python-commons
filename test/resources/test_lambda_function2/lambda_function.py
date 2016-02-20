import logging

logger = logging.getLogger()
logging.basicConfig()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Updated function source")
    logger.info("Event: " + str(event))
    logger.info("Context:" + str(context))