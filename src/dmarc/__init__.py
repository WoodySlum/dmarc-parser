#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC support library """

import logging
import os

from pathlib import Path
from threading import Thread

from .parser import DmarcParser

class _ParseFile(Thread):
    """
    A threaded class for the DmarcParser.
    Part of the support library and should not be used directly.
    """
    def __init__(self, file, debug_level=logging.INFO):
        Thread.__init__(self)
        self.parser = DmarcParser(debug_level)
        self.file = file
    def run(self):
        self.parser.read_file(self.file)


def dmarc_from_folder(folder, recursive=False, debug_level=logging.INFO):
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

    threads = []
    for file in files_found:
        threads.append(_ParseFile(file, debug_level))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

def dmarc_from_file(file, debug_level=logging.INFO):
    """ Parse a file """
    if not os.path.exists(file):
        return None
    if not os.path.isfile(file):
        return None
    parser = DmarcParser(debug_level)
    parser.read_file(Path(file))

    return None # Returns None for now. Should be dict from parser
