[![Package](https://github.com/andersnauman/dmarc-parser/actions/workflows/python-package.yml/badge.svg)](https://github.com/andersnauman/dmarc-parser/actions/workflows/python-package.yml) [![Pylint](https://github.com/andersnauman/dmarc-parser/actions/workflows/pylint.yml/badge.svg)](https://github.com/andersnauman/dmarc-parser/actions/workflows/pylint.yml)
## DMARC Parser
### Public helper methods
These methods are only included for your convenience. Code is "not" part of the main library/parser but acts as a great segway to implement the parser with ease.
```
    from dmarc import dmarc_from_folder, dmarc_from_file

    Multi-threaded:    dmarc_from_folder(folder: str, recursive: bool, debug_level: int)
    Single-threaded:   dmarc_from_file(path: str, debug_level: int):
```

### Public class / methods
```
    DmarcParser(queue_name: str, queue: Queue, debug_level: int)        # Queue is for logging and optional. 
        .read_file(path: str)
        .extract_report_from_zip(data: io.BytesIO) -> dict
        .extract_report_from_gzip(data: io.BytesIO) -> dict
        .extract_report_from_xml(data: bytes) -> dict
        .extract_report_from_eml(data: bytes) -> dict
```

### Minimal example program
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Main """

import argparse
import logging

from dmarc import dmarc_from_folder

def run(debug_level=logging.INFO):
    """ Main """
    dmarc_from_folder("example/private/data/", recursive=True, debug_level=debug_level)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    args = parser.parse_args()
    run_args = {}
    if args.verbose:
        run_args["debug_level"] = logging.DEBUG
    run(**run_args)
```

### Install instructions
```
# Production
pip install .

# Development
## Setup
python -m venv env
.\env\Scripts\activate

## Install
pip install .

## Test
python -m pytest
```