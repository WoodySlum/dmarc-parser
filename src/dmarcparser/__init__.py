#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC support library """

import logging
import os

from pathlib import Path
from multiprocessing import Queue
from multiprocessing import Process

from .parser import DmarcParser
from .logger import _custom_logger, _queue_logging

class InvalidPath(Exception):
    """ Exception raised when path is not valid """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidFile(Exception):
    """ Exception raised when file is not valid """
    def __init__(self, msg):
        super().__init__(msg)

# pylint: disable-next=line-too-long
def _parse_file(path: str = None, logger_name: str = None, logger_queue: Queue = None, log_level: int = logging.INFO):
    """
    A method to support multiprocessing.
    Part of the support library and should not be used directly.
    """
    _logger = _custom_logger(
        logger_name=logger_name,
        queue=logger_queue,
        log_level=log_level,
    )
    parser = DmarcParser(_logger)
    parser.read_file(path)

def dmarc_from_folder(folder: str, recursive: bool = False, log_level: int = logging.INFO):
    """
    Parsing a folder, recursivly if needed, through multiprocessing.
    This method is provided for you convenience, although, writing your own is always recommended.
    Especially if you want a different logging handler than default (stdout + syslog).
    """
    if not os.path.exists(folder):
        return
    if not os.path.isdir(folder):
        return

    files_found = []
    if recursive:
        for root, _, files in os.walk(folder):
            files_found.extend([Path(root) / f for f in files])
    else:
        files_found = [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]

    logger_queue = Queue()
    logger_name = "app"
    logger_p = Process(target=_queue_logging, args=(logger_name, logger_queue, log_level))
    logger_p.start()

    threads = []
    for path in files_found:
        threads.append(
            Process(target=_parse_file, args=(path, logger_name, logger_queue, log_level))
        )

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    # Write 'None' do exit the loop inside _queue_logging().
    logger_queue.put(None)
    logger_p.join()

def dmarc_from_file(path: str, log_level: int = logging.INFO) -> dict|None:
    """ Parse a file """
    if not os.path.exists(path):
        raise InvalidPath
    if not os.path.isfile(path):
        raise InvalidFile

    parser = DmarcParser(log_level=log_level)
    return parser.read_file(Path(path))
