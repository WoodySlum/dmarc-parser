#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC report library """

import io
import xml.etree.ElementTree as elementTree

from datetime import datetime
from dataclasses import dataclass, asdict
from email import message_from_bytes
from email import policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

from ipaddress import IPv4Address, IPv6Address, ip_address

from .misc import _sanitize_input
from .exceptions import InvalidTime, InvalidOrgName, InvalidFormat
from .exceptions import InvalidForensicReport, InvalidForensicSample

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
    record_spf_domain: str = None
    record_spf_result: str = None

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
        return {
            "report": {
                "metadata": {**asdict(self.metadata)},
                "policy": {**asdict(self.policy)},
                "records": [asdict(record) for record in self.records],
            },
        }

    def __str__(self):
        return f"<{self.metadata.org_name}, {self.metadata.email}>"

# https://www.rfc-editor.org/rfc/rfc6591.txt
# AFRF
@dataclass
# pylint: disable-next=too-many-instance-attributes
class ForensicReportData:
    """ Dataclass for the forensic report. Contains all the possible fields from the RFC """
    arrival_date: datetime = None
    auth_failure: str = None
    authentication_results: str = None
    dkim_canonicalized_header: str = None
    dkim_canonicalized_body: str = None
    dkim_domain: str = None
    dkim_identity: str = None
    dkim_selector: str = None
    delivery_result: str = None
    feedback_type: str = None
    identity_alignment: str = None
    incidents: int = None
    original_envelope_id: str|list = None
    original_mail_from: str = None
    original_rcpt_to: str|list = None
    reported_domain: str = None
    reported_uri: str|list = None
    reporting_mta: str = None
    source_ipv4: IPv4Address = None
    source_ipv6: IPv6Address = None
    user_agent: str = None
    version: int = None

class ForensicReport():
    """
    A forensic report class to organize and validate data.
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

        if not isinstance(data, bytes):
            raise ValueError("Sample data are not bytes")

        self.sample_data = message_from_bytes(data, _class=EmailMessage)

    def get_dict(self) -> dict:
        """ d """
        report = asdict(self.report_data)
        sample = {}
        if isinstance(self.sample_data, EmailMessage):
            for key, value in self.sample_data.items():
                sample[key] = value
        return {"report": {**report}, "sample": {**sample}}

    def is_report_valid(self) -> bool:
        """ d """
        match self.report_data.feedback_type:
            case "abuse":
                required_fields = [
                    self.report_data.feedback_type,
                    self.report_data.user_agent,
                    self.report_data.version,
                    self.report_data.reported_domain,
                    self.report_data.authentication_results,
                ]
            case "auth-failure":
                required_fields = [
                    self.report_data.feedback_type,
                    self.report_data.user_agent,
                    self.report_data.version,
                    self.report_data.reported_domain,
                    self.report_data.authentication_results,
                    self.report_data.auth_failure,
                ]
            case _:
                required_fields = []

        counter = 0
        for field in required_fields:
            counter += 1
            if field:
                continue
            print("missing field: ", field, counter)
            return False

        return True

    def is_sample_valid(self) -> bool:
        """ d """
        return True

    def __repr__(self):
        """ d """
        return str(self.get_dict())

# pylint: disable-next=too-many-locals, too-many-statements
def aggregate_report_from_xml(xml: bytes) -> AggregateReport:
    """ d """

    if not isinstance(xml, bytes):
        raise ValueError("Input variable is not bytes")

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

# pylint: disable-next=too-many-locals, too-many-branches, too-many-statements
def forensic_report_from_string(report: str, sample: str) -> ForensicReport:
    """ d """
    forensic_report = ForensicReport()
    forensic_report_data = ForensicReportData()

    # Report
    if not isinstance(report, bytes):
        try:
            report = report.encode("utf-8")
        except (UnicodeDecodeError, AttributeError) as _error:
            raise ValueError("Could not encode report") from _error

    msg = message_from_bytes(report, _class=EmailMessage, policy=policy.default)
    for key, value in msg.items():
        key = key.lower().strip()
        value = value.strip()

        match key:
            case "arrival-date" | "received-date": # optional, once
                if forensic_report_data.arrival_date is not None:
                    raise InvalidFormat("Arrival-/Received-date is used multiple times")
                try:
                    time = parsedate_to_datetime(value)
                except ValueError as _error:
                    raise InvalidTime("Date could not be parsed") from _error
                forensic_report_data.arrival_date = time
            case "auth-failure": # required, adsp/bodyhash/revoked/signature/spf
                if forensic_report_data.auth_failure is not None:
                    raise InvalidFormat("Auth-Failure is used multiple times")
                forensic_report_data.auth_failure = value
            case "authentication-results": # required, once
                if forensic_report_data.authentication_results is not None:
                    raise InvalidFormat("Authentication-Results is used multiple times")
                forensic_report_data.authentication_results = value
            case "delivery-result": # optional, delivered/spam/policy/reject/other
                forensic_report_data.delivery_result = value
            case "dkim-canonicalized-header":
                forensic_report_data.dkim_canonicalized_header = value
            case "dkim_canonicalized_body":
                forensic_report_data.dkim_canonicalized_body = value
            case "dkim-domain":
                forensic_report_data.dkim_domain = value
            case "dkim-identity":
                forensic_report_data.dkim_identity = value
            case "dkim-selector":
                forensic_report_data.dkim_selector = value
            case "feedback-type": # required, once, auth-failure/abuse/fraud/viurs/other
                if forensic_report_data.feedback_type is not None:
                    raise InvalidFormat("Feedback-type is used multiple times")
                forensic_report_data.feedback_type = value
            case "identity-alignment":
                forensic_report_data.identity_alignment = value
            case "incidents": # optional, once
                if forensic_report_data.incidents is not None:
                    raise InvalidFormat("Incidents is used multiple times")
                forensic_report_data.incidents = value
            case "reported-domain": # required
                if forensic_report_data.reported_domain is not None:
                    raise InvalidFormat("Reported-Domain is used multiple times")
                forensic_report_data.reported_domain = value
            case "reporting-mta": # optional, once
                if forensic_report_data.reporting_mta is not None:
                    raise InvalidFormat("Reporting-MTA is used multiple times")
                forensic_report_data.reporting_mta = value
            case "original-envelope-id": # optional
                original_envelope_id = forensic_report_data.original_envelope_id
                forensic_report_data.original_envelope_id = _add_string(original_envelope_id, value)
            case "original-mail-from": # optional, once
                if forensic_report_data.original_mail_from is not None:
                    raise InvalidFormat("Original-Mail-From is used multiple times")
                forensic_report_data.original_mail_from = value
            case "original-rcpt-to": # optional
                original_rcpt_to = forensic_report_data.original_rcpt_to
                forensic_report_data.original_rcpt_to = _add_string(original_rcpt_to, value)
            case "reported-uri": # optional
                reported_uri = forensic_report_data.reported_uri
                forensic_report_data.reported_uri = _add_string(reported_uri, value)
            case "source-ip": # optional, once
                if forensic_report_data.source_ipv4 is not None or \
                    forensic_report_data.source_ipv6 is not None:
                    raise InvalidFormat("Source-IP is used multiple times")
                try:
                    ip_addr = ip_address(value)
                except ValueError as _error:
                    raise ValueError("Source-IP could not be parsed") from _error
                if isinstance(ip_addr, IPv4Address):
                    forensic_report_data.source_ipv4 = ip_addr
                elif isinstance(ip_addr, IPv6Address):
                    forensic_report_data.source_ipv6 = ip_addr
            case "user-agent": # required, once
                if forensic_report_data.user_agent is not None:
                    raise InvalidFormat("User-Agent is used multiple times")
                forensic_report_data.user_agent = value
            case "version": # required, once
                if forensic_report_data.version is not None:
                    raise InvalidFormat("Version is used multiple times")
                if not isinstance(value, int):
                    try:
                        value = int(value)
                    except ValueError as _error:
                        raise InvalidFormat("") from _error
                forensic_report_data.version = value
            case _:
                print("Unknown: ", key, value)
                continue
                #raise UnknownKey(f"The report contains an unknown key ({key})")

    forensic_report.add_report_data(forensic_report_data)
    if not forensic_report.is_report_valid():
        raise InvalidForensicReport("Forensic report is missing required fields")

    # Sample
    try:
        sample = sample.encode("utf-8") if not isinstance(sample, bytes) else sample
    except (UnicodeDecodeError, AttributeError) as _error:
        # pylint: disable-next=line-too-long
        raise InvalidForensicSample(f"Forensic sample could not be encoded: {str(_error)}") from _error

    forensic_report.add_sample_data(sample)
    if not forensic_report.is_sample_valid():
        raise InvalidForensicReport("Forensic sample is missing required fields")

    return forensic_report

def _add_string(original: str|list, new_value: str) -> str|list:
    """ A simple function to convert a string to list if there are multiple values """
    if original is None:
        return new_value

    if isinstance(original, list):
        original.append(new_value)
        return original

    return [original, new_value]
