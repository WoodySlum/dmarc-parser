#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC logger library """

import sys
import logging
import itertools

from sys import platform

from multiprocessing import Queue
from logging.handlers import QueueHandler, SysLogHandler

SYSLOG_TO_FILE = 1 << 0
SYSLOG_TO_SCREEN = 1 << 1
SYSLOG_TO_SYSLOG = 1 << 2

unique_id = itertools.count()

def _unique_logger_id():
    return "dmarcparser-" + str(next(unique_id))

# pylint: disable-next=line-too-long
def _custom_logger(logger_name=_unique_logger_id(), queue: Queue = None, log_level:int = logging.INFO, handler:int = SYSLOG_TO_SCREEN):
    """
    Part of the support library and should not be used directly.
    Used if no logger is provided to main functions.
    The recommendation is to always include your own.

    Create a custom logger instead of modifing the core logger
    https://stackoverflow.com/questions/28330317/print-timestamp-for-logging-in-python
    """

    formatter = logging.Formatter(fmt='%(asctime)s %(thread)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

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

    if handler & SYSLOG_TO_SYSLOG:
        if platform.startswith('linux'):
            syslog_handler = SysLogHandler(facility=SysLogHandler.LOG_DAEMON, address='/dev/log')
            logger.addHandler(syslog_handler)
        else:
            logger.debug("SYSLOG_TO_SYSLOG is only supported for Linux")

    return logger

def _queue_logging(logger_name: str = None, queue: Queue = None, log_level=logging.INFO):
    """
    A method to support multiprocessing.
    Part of the support library and should not be used directly.
    """
    logger = _custom_logger(
        logger_name=logger_name,
        log_level=log_level,
        handler=SYSLOG_TO_SCREEN | SYSLOG_TO_FILE | SYSLOG_TO_SYSLOG,
    )

    while True:
        message = queue.get()
        if message is None:
            break
        logger.handle(message)
