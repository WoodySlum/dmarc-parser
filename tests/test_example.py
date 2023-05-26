#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Test module """

from dmarc import dmarc_from_file

def test_normal():
    """ Test a normal """
    assert dmarc_from_file("example/example.xml") is None
