#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Test module """

from dmarcparser import Parse

parser = Parse()

def test_normal():
    """ Test a normal """
    assert parser.parsefile("example/report1.zip") == {"org_name": "example.com"}
