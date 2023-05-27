#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC logger library """

import sys
import logging
import itertools

from multiprocessing import Queue
from logging.handlers import QueueHandler

SYSLOG_TO_FILE = 1 << 0
SYSLOG_TO_SCREEN = 1 << 1

unique_id = itertools.count()

def _unique_logger_id():
    return "dmarcparser-" + str(next(unique_id))

# pylint: disable-next=line-too-long
def _custom_logger(name=_unique_logger_id(), queue: Queue = None, debug_level=logging.INFO, handler=SYSLOG_TO_SCREEN):
    """
    Create a custom logger instead of modifing the core logger
    https://stackoverflow.com/questions/28330317/print-timestamp-for-logging-in-python
    """
    formatter = logging.Formatter(fmt='%(asctime)s %(thread)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(name)
    logger.setLevel(debug_level)

    if queue is not None:
        logger.addHandler(QueueHandler(queue))
        return logger

    if handler & SYSLOG_TO_FILE:
        file_handler = logging.FileHandler('log.txt', mode='w')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if handler & SYSLOG_TO_SCREEN:
        screen_handler = logging.StreamHandler(stream=sys.stdout)
        screen_handler.setFormatter(formatter)
        logger.addHandler(screen_handler)

    return logger

def logging_process(name, queue: Queue, debug_level=logging.INFO):
    """ s """
    logger = _custom_logger(
        name=name,
        debug_level=debug_level,
        handler=SYSLOG_TO_SCREEN | SYSLOG_TO_FILE,
    )

    while True:
        message = queue.get()
        if message is None:
            break
        logger.handle(message)
