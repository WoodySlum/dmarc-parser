#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC report library """

from datetime import datetime

from .misc import _sanitize_input

class InvalidTime(Exception):
    """ Exception raised for errors in the input for time """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidOrgName(Exception):
    """ Exception raised for error in the organization name """
    def __init__(self, msg):
        super().__init__(msg)

class AggregateReport():
    """
    An aggregated report class to organize and validate data from xml.
    """
    def __init__(self):
        self.dict = {}
        self.org_name = ""
        self.email = ""

    def set_org_name(self, org_name):
        """ d """
        self.dict["org_name"] = _sanitize_input(org_name)
        self.org_name = _sanitize_input(org_name)
        if not self.org_name:
            raise InvalidOrgName("Organization name cannot be empty")

    def set_email(self, email):
        """ d """
        self.dict["email"] = _sanitize_input(email)
        self.email = _sanitize_input(email)

    def set_report_id(self, report_id):
        """ d """
        self.dict["report_id"] = _sanitize_input(report_id)

    def set_date_begin(self, date_begin):
        """ d """
        if not isinstance(date_begin, int):
            try:
                date_begin = int(date_begin)
            except ValueError:
                date_begin = 0
        if datetime.fromtimestamp(date_begin) > datetime.now():
            raise InvalidTime("Date begin is in the future")
        self.dict["date_begin"] = date_begin

    def set_date_end(self, date_end):
        """ d """
        if not isinstance(date_end, int):
            try:
                date_end = int(date_end)
            except ValueError:
                date_end = 0
        if datetime.fromtimestamp(date_end) > datetime.now():
            raise InvalidTime("Date end is in the future")
        self.dict["date_end"] = date_end

    def get_dict(self):
        """ d """
        return self.dict

    def __str__(self):
        return f"<{self.org_name}, {self.email}>"

class ForensicReport():
    """
    s
    """
    def __init__(self):
        self.dict = {}

    def get_dict(self):
        """ d """
        return self.dict

    def __repr__(self):
        """ d """
        return "hej"
