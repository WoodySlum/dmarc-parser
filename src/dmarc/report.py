#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC report library """

import io
import xml.etree.ElementTree as elementTree

from datetime import datetime
from dataclasses import dataclass
from email import message_from_bytes
from email.message import EmailMessage
from ipaddress import IPv4Address, IPv6Address, ip_address

from .misc import _sanitize_input

class InvalidTime(Exception):
    """ Exception raised for errors in the input for time """
    def __init__(self, msg):
        super().__init__(msg)

class InvalidOrgName(Exception):
    """ Exception raised for error in the organization name """
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

# RFC 7489
# https://datatracker.ietf.org/doc/html/rfc7489

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

@dataclass
# pylint: disable-next=too-many-instance-attributes
class Record:
    """ d """
    record_source_ipv4: IPv4Address = None
    record_source_ipv6: IPv6Address = None
    record_count: int = None

    # Row / Policy Evaluated
    record_eval_disposition: str = None
    record_eval_dkim: str = None
    record_eval_spf: str = None

    # Identifiers
    record_header_from: str = None

    # Auth Results
    record_spf_domain:str = None
    record_spf_result:str = None

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
        self.metadata.org_name = _sanitize_input(org_name)
        if not self.metadata.org_name:
            raise InvalidOrgName("Organization name cannot be empty")

    def set_email(self, email):
        """ d """
        self.metadata.email = _sanitize_input(email)

    def set_report_id(self, report_id):
        """ d """
        self.metadata.report_id = _sanitize_input(report_id)

    def set_date_begin(self, date_begin):
        """ d """
        if not isinstance(date_begin, int):
            try:
                date_begin = int(date_begin)
            except ValueError:
                date_begin = 0
        if date_begin == 0 or datetime.fromtimestamp(date_begin) > datetime.now():
            raise InvalidTime("Date begin is in the future")
        self.metadata.date_begin = date_begin

    def set_date_end(self, date_end):
        """ d """
        if not isinstance(date_end, int):
            try:
                date_end = int(date_end)
            except ValueError:
                date_end = 0
        if date_end == 0 or datetime.fromtimestamp(date_end) > datetime.now():
            raise InvalidTime("Date end is in the future")
        self.metadata.date_end = date_end

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

    def add_record(self, record):
        """ d """
        if isinstance(record, Record):
            self.records.append(record)
        else:
            raise ValueError

    def get_dict(self):
        """ d """
        return self.dict

    def __str__(self):
        return f"<{self.metadata.org_name}, {self.metadata.email}>"

@dataclass
# pylint: disable-next=too-many-instance-attributes
class ForensicReportData:
    """ d """
    feedback_type: str = None
    user_agent: str = None
    version: int = None
    original_mail_from: str = None
    arrival_date: datetime = None
    source_ipv4: IPv4Address = None
    source_ipv6: IPv6Address = None
    reported_domain: str = None
    original_envelope_id: str = None
    authentication_results: str = None
    dkim_domain: str = None
    delivery_result: str = None
    identity_alignment: str = None

class ForensicReport():
    """
    s
    """
    def __init__(self):
        self.dict = {}

        self.report_data = None  # ForensicReportData()
        self.sample_data = None  # EmailMessage()

    def add_report_data(self, data: ForensicReportData):
        """ s """
        self.report_data = data

    def add_sample_data(self, data: bytes):
        """ s """
        try:
            data = data.encode("utf-8") if not isinstance(data, bytes) else data
        except (UnicodeDecodeError, AttributeError) as _error:
            raise InvalidForensicSample("Forensic sample could not be encoded") from _error

        self.sample_data = message_from_bytes(data, _class=EmailMessage)

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
        ## Source ip
        record_source_ip = record.find("row/source_ip")
        # pylint: disable-next=line-too-long
        record_source_ip = "" if record_source_ip is None or record_source_ip.text is None else record_source_ip.text
        try:
            ip_addr = ip_address(record_source_ip)
        except ValueError:
            continue
        ipv4_addr = None
        ipv6_addr = None
        if isinstance(ip_addr, IPv4Address):
            ipv4_addr = ip_addr
        elif isinstance(ip_addr, IPv6Address):
            ipv6_addr = ip_addr
        ## Record cound
        record_count = record.find("row/count")
        record_count = 0 if record_count is None or record_count.text is None else record_count.text

        # Row / Policy Evaluated
        ## Disposition
        record_eval_disposition = record.find("row/policy_evaluated/disposition")
        # pylint: disable-next=line-too-long
        record_eval_disposition = "" if record_eval_disposition is None or record_eval_disposition.text is None else record_eval_disposition.text
        ## Evaluated DKIM
        record_eval_dkim = record.find("row/policy_evaluated/dkim")
        # pylint: disable-next=line-too-long
        record_eval_dkim = "" if record_eval_dkim is None or record_eval_dkim.text is None else record_eval_dkim.text
        ## Evaluated SPF
        record_eval_spf = record.find("row/policy_evaluated/spf")
        # pylint: disable-next=line-too-long
        record_eval_spf = "" if record_eval_spf is None or record_eval_spf is None else record_eval_spf.text

        # Identifiers
        ## Header-from
        record_header_from = record.find("identifiers/header_from")
        # pylint: disable-next=line-too-long
        record_header_from = "" if record_header_from is None or record_header_from is None else record_header_from.text

        # Auth Results
        ## SPF Domain
        record_spf_domain = record.find("auth_results/spf/domain")
        # pylint: disable-next=line-too-long
        record_spf_domain = "" if record_spf_domain is None or record_spf_domain.text is None else record_spf_domain.text
        ## SPF Result
        record_spf_result = record.find("auth_results/spf/result")
        # pylint: disable-next=line-too-long
        record_spf_result = "" if record_spf_result is None or record_spf_result.text is None else record_spf_result.text

        aggregate_report.add_record(
            Record(
                ipv4_addr,
                ipv6_addr,
                record_count,
                record_eval_disposition,
                record_eval_dkim,
                record_eval_spf,
                record_header_from,
                record_spf_domain,
                record_spf_result,
            )
        )

    return aggregate_report

# pylint: disable-next=too-many-locals, too-many-branches
def forensic_report_from_string(report: str, sample: str) -> ForensicReport:
    """ d """
    forensic_report = ForensicReport()
    forensic_report_data = ForensicReportData()

    raw_report = report
    for line in raw_report.splitlines():
        key, value = line.split(":", 1)
        key = key.lower().strip()
        value = value.strip()

        if key == "feedback-type":
            forensic_report_data.feedback_type = value
        elif key == "user-agent":
            forensic_report_data.user_agent = value
        elif key == "version":
            forensic_report_data.version = value
        elif key == "original-mail-from":
            forensic_report_data.original_mail_from = value
        elif key == "arrival-date":
            try:
                time = datetime.strptime(value, "%a, %d %b %Y %H:%M:%S %z")
            except ValueError as _error:
                raise InvalidTime from _error

            forensic_report_data.arrival_date = time
        elif key == "source-ip":
            try:
                ip_addr = ip_address(value)
            except ValueError as _error:
                raise ValueError from _error

            if isinstance(ip_addr, IPv4Address):
                forensic_report_data.source_ipv4 = ip_addr
            elif isinstance(ip_addr, IPv6Address):
                forensic_report_data.source_ipv6 = ip_addr
        elif key == "reported-domain":
            forensic_report_data.reported_domain = value
        elif key == "original-envelope-id":
            forensic_report_data.original_envelope_id = value
        elif key == "authentication-results":
            forensic_report_data.authentication_results = value
        elif key == "dkim-domain":
            forensic_report_data.dkim_domain = value
        elif key == "delivery-result":
            forensic_report_data.delivery_result = value
        elif key == "identity-alignment":
            forensic_report_data.identity_alignment = value
        else:
            raise UnknownKey(f"The report contains an unknown key ({key})")

    forensic_report.report_data = forensic_report_data

    # Sample
    try:
        sample = sample.encode("utf-8") if not isinstance(sample, bytes) else sample
    except (UnicodeDecodeError, AttributeError) as _error:
        raise InvalidForensicSample("Forensic sample could not be encoded") from _error
    forensic_report.add_sample_data(sample)

    return forensic_report
