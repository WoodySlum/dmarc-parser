#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC misc library """

import html

def _sanitize_input(string: str) -> str:
    """ Sanitize a string to not wreak havoc """
    return html.escape(string)
