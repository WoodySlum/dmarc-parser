#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Test module """

from dmarcparser import dmarc_from_file

def test_normal():
    """ Test a normal """
    res = dmarc_from_file("example/example.xml")
    assert res is not None
