[![Package](https://github.com/andersnauman/dmarc-parser/actions/workflows/python-package.yml/badge.svg)](https://github.com/andersnauman/dmarc-parser/actions/workflows/python-package.yml) [![Pylint](https://github.com/andersnauman/dmarc-parser/actions/workflows/pylint.yml/badge.svg)](https://github.com/andersnauman/dmarc-parser/actions/workflows/pylint.yml)
## DMARC Parser
### Public helper functions
```
    dmarc_from_folder(folder: str, recursive: bool, debug_level: int)
    dmarc_from_file(path: str, debug_level: int):
```

`Please note: dmarc_from_folder() is, by default, multi-threaded (using multiprocessing), while dmarc_from_file() is not`

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