import logging

def set_logger(level=None):
    if level is None:
        level = logging.INFO
    logger = logging.getLogger()
    logging.basicConfig()
    logger.setLevel(level)
    return logger