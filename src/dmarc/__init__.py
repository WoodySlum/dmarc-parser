#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC support library """

import logging
import os

from pathlib import Path
from multiprocessing import Queue
from multiprocessing import Process

from .parser import DmarcParser
from .logger import logging_process

def _parse_file(path: str, queue_name: str, queue: Queue, debug_level: int = logging.INFO):
    """
    A method to support multiprocessing.
    Part of the support library and should not be used directly.
    """

    parser = DmarcParser(queue, queue_name, debug_level)
    parser.read_file(path)

def dmarc_from_folder(folder: str, recursive: bool = False, debug_level: int = logging.INFO):
    """ Parse a folder """
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

    queue = Queue()
    queue_name = "app"
    logger_p = Process(target=logging_process, args=(queue_name, queue, debug_level,))
    logger_p.start()

    threads = []
    counter = 0
    for path in files_found:
        threads.append(Process(target=_parse_file, args=(path, queue_name, queue, debug_level,)))
        counter += 1
        if counter > 1:
            break

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    queue.put(None)
    logger_p.join()

def dmarc_from_file(path: str, debug_level: int = logging.INFO):
    """ Parse a file """
    if not os.path.exists(path):
        return None
    if not os.path.isfile(path):
        return None
    parser = DmarcParser(debug_level)
    parser.read_file(Path(path))

    return None # Returns None for now. Should be dict from parser
