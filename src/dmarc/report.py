#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC report library """

import io
import xml.etree.ElementTree as elementTree

from datetime import datetime
from dataclasses import dataclass

from .misc import _sanitize_input

class InvalidTime(Exception):
    """ Exception raised for errors in the input for time """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidOrgName(Exception):
    """ Exception raised for error in the organization name """
    def __init__(self, msg):
        super().__init__(msg)

@dataclass
class Metadata:
    """ d """
    org_name: str = None
    email: str = None
    report_id: str = None
    date_begin: datetime = None
    date_end: datetime = None

@dataclass
class PolicyPublished:
    """ d """
    policy_domain: str = None
    policy_adkim: str = None
    policy_aspf: str = None
    policy_p: str = None
    policy_sp: str = None
    policy_pct: int = None

class AggregateReport():
    """
    An aggregated report class to organize and validate data from xml.
    """
    def __init__(self):
        self.dict = {}

        # Report metadata
        self.metadata = Metadata()

        # Policy published
        self.policy = PolicyPublished()

        # Records
        self.records = []

    def is_valid(self):
        """ Test if the class got all the necessary data """
        return True

    def set_org_name(self, org_name):
        """ d """
        self.dict["org_name"] = _sanitize_input(org_name)
        self.metadata.org_name = _sanitize_input(org_name)
        if not self.metadata.org_name:
            raise InvalidOrgName("Organization name cannot be empty")

    def set_email(self, email):
        """ d """
        self.dict["email"] = _sanitize_input(email)
        self.metadata.email = _sanitize_input(email)

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

    def set_policy_domain(self, domain):
        """ d """
        self.policy.policy_domain = _sanitize_input(domain)

    def set_policy_adkim(self, adkim):
        """ d """
        self.policy.policy_adkim = _sanitize_input(adkim)

    def set_policy_aspf(self, policy_aspf):
        """ d """
        self.policy.policy_aspf = _sanitize_input(policy_aspf)

    def set_policy_p(self, policy_p):
        """ d """
        self.policy.policy_p = _sanitize_input(policy_p)

    def set_policy_sp(self, policy_sp):
        """ d """
        self.policy.policy_sp = _sanitize_input(policy_sp)

    def set_policy_pct(self, policy_pct):
        """ d """
        self.policy.policy_pct = _sanitize_input(policy_pct)

    def get_dict(self):
        """ d """
        return self.dict

    def __str__(self):
        return f"<{self.metadata.org_name}, {self.metadata.email}>"

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

# pylint: disable-next=too-many-locals, too-many-statements
def aggregate_report_from_xml(xml: str) -> AggregateReport:
    """ d """
    aggregate_report = AggregateReport()

    tree = elementTree.parse(io.BytesIO(xml))
    root = tree.getroot()
    #self.logger.debug([elem.tag for elem in tree.getroot().iter()])

    # Parse <report_metadata>
    ## Organization Name
    org_name = root.find("./report_metadata/org_name")
    org_name = "" if org_name is None or org_name.text is None else org_name.text
    aggregate_report.set_org_name(org_name)

    ## Email
    email = root.find("./report_metadata/email")
    email = "" if email is None or email.text is None else email.text
    aggregate_report.set_email(email)

    ## Report ID
    report_id = root.find("./report_metadata/report_id")
    report_id = "" if report_id is None or report_id.text is None else report_id.text
    aggregate_report.set_report_id(report_id)

    ## Start time of the report
    date_begin = root.find("./report_metadata/date_range/begin")
    date_begin = 0 if date_begin is None or date_begin.text is None else date_begin.text
    aggregate_report.set_date_begin(date_begin)

    ## End time of the report
    date_end = root.find("./report_metadata/date_range/end")
    date_end = 0 if date_end is None or date_end is None else date_end.text
    aggregate_report.set_date_end(date_end)

    # Parse <policy_published>
    ## Domain
    policy_domain = root.find("./policy_published/domain")
    # pylint: disable-next=line-too-long
    policy_domain = "" if policy_domain is None or policy_domain.text is None else policy_domain.text
    aggregate_report.set_policy_domain(policy_domain)

    ## DKIM
    policy_adkim = root.find("./policy_published/adkim")
    policy_adkim = "" if policy_adkim is None or policy_adkim.text is None else policy_adkim.text
    aggregate_report.set_policy_adkim(policy_adkim)

    # SPF
    policy_aspf = root.find("./policy_published/aspf")
    policy_aspf = "" if policy_aspf is None or policy_aspf.text is None else policy_aspf.text
    aggregate_report.set_policy_aspf(policy_aspf)

    ## Domain policy
    policy_p = root.find("./policy_published/p")
    policy_p = "" if policy_p is None or policy_p.text is None else policy_p.text
    aggregate_report.set_policy_p(policy_p)

    ## Sub-domanin policy
    policy_sp = root.find("./policy_published/sp")
    policy_sp = "" if policy_sp is None or policy_sp.text is None else policy_sp.text
    aggregate_report.set_policy_sp(policy_sp)

    ## Percentage of block
    policy_pct = root.find("./policy_published/pct")
    policy_pct = "" if policy_pct is None or policy_pct.text is None else policy_pct.text
    aggregate_report.set_policy_pct(policy_pct)

    # Parse <records>
    for record in root.findall("./record"):
        # Row
        source_ip = record.find("row/source_ip")
        count = record.find("row/count")

        # Row / Policy Evaluated
        disposition = record.find("row/policy_evaluated/disposition")
        dkim = record.find("row/policy_evaluated/dkim")
        spf = record.find("row/policy_evaluated/spf")

        # Identifiers
        header_from = record.find("identifiers/header_from")

        # Auth Results
        domain = record.find("auth_results/spf/result")
        result = record.find("auth_results/spf/domain")

        print(source_ip.text)
        print(count.text)
        print(header_from.text)
        print(disposition.text)
        print(dkim.text)
        print(spf.text)
        print(domain.text)
        print(result.text)

    return aggregate_report

def forensic_report_from_xml(report: str, sample: str) -> ForensicReport:
    """ d """
    forensic_report = ForensicReport()

    raw_report = report
    for line in raw_report.splitlines():
        print(line)
    raw_sample = sample
    for line in raw_sample.splitlines():
        print(line)

    return forensic_report
