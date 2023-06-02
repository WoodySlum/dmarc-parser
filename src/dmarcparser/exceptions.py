#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" Exceptions """

class InvalidTime(Exception):
    """ Exception raised for errors in the input for time """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidOrgName(Exception):
    """ Exception raised for error in the organization name """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidForensicReport(Exception):
    """ Exception raised for error in the report """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidForensicSample(Exception):
    """ Exception raised for error in the sample """
    def __init__(self, msg):
        super().__init__(msg)

class UnknownKey(Exception):
    """ Exception raised for unknown keys in the key/value pairs """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidFormat(Exception):
    """ Exception raised when data do not follow RFC """
    def __init__(self, msg):
        super().__init__(msg)
