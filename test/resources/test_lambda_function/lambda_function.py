import logging

logger = logging.getLogger()
logging.basicConfig()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Hello World!")
    logger.info("Event: " + str(event))
    logger.info("Context:" + str(context))