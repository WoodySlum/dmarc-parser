#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC report library """

import io
import re
import xml.etree.ElementTree as elementTree

from datetime import datetime
from dataclasses import dataclass, asdict
from email import message_from_bytes
from email import policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime, parseaddr

from ipaddress import ip_address

from .misc import _sanitize_input
from .exceptions import InvalidTime, InvalidOrgName, InvalidFormat
from .exceptions import InvalidForensicReport, InvalidForensicSample

# RFC 7489
# https://datatracker.ietf.org/doc/html/rfc7489

@dataclass
class EmailAddress():
    """ d """
    address: str = None
    name: str = None

@dataclass
class Metadata:
    """ d """
    org_name: str = None
    email: EmailAddress = None
    report_id: str = None
    date_begin: datetime = None
    date_end: datetime = None

@dataclass
# pylint: disable-next=too-many-instance-attributes
class PolicyPublished:
    """ d """
    domain: str = None
    adkim: str = None
    aspf: str = None
    # pylint: disable-next=invalid-name
    p: str = None
    # pylint: disable-next=invalid-name
    sp: str = None
    pct: int = None

@dataclass
class DKIM:
    """ d """
    domain: str = None
    selector : str = None
    result: str = None # none / pass / fail / policy / neutral / temperror / permerror
    human_result: str = None

@dataclass
class SPF:
    """ SPF """
    domain: str = None
    result: str = None # none / neutral / pass / fail / softfail / temperror / permerror
    scope: str = None # helo / mfrom

@dataclass
class Identifiers:
    """ Identifiers """
    header_from: str = None
    envelope_from: str = None
    envelope_to: str = None

@dataclass
class AuthResults:
    """ Auth Results """
    spf: SPF = None
    dkim: DKIM = None

@dataclass
class PolicyEvaluated:
    """ s """
    dkim: str = None
    disposition: str = None
    spf: str = None

@dataclass
class Row:
    """ d """
    count: int = None
    source_ip: str = None
    policy_evaluated: PolicyEvaluated = None

@dataclass
# pylint: disable-next=too-many-instance-attributes
class Record:
    """ d """
    rows: list[Row] = None
    identifiers: Identifiers = None
    auth_results: AuthResults = None

class AggregateReport():
    """
    An aggregated report class to organize and validate data from xml.
    """
    def __init__(self):
        self.dict = {}

        # Report metadata
        self.metadata = Metadata()

        # Policy published
        self.policy_published = PolicyPublished()

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
        name, address = parseaddr(email)
        self.metadata.email = EmailAddress(
            address = _sanitize_input(address),
            name = _sanitize_input(name)
        )

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
        self.metadata.date_begin = datetime.fromtimestamp(date_begin)

    def set_date_end(self, date_end):
        """ d """
        if not isinstance(date_end, int):
            try:
                date_end = int(date_end)
            except ValueError:
                date_end = 0
        if date_end == 0 or datetime.fromtimestamp(date_end) > datetime.now():
            raise InvalidTime("Date end is in the future")
        self.metadata.date_end = datetime.fromtimestamp(date_end)

    def set_policy_domain(self, domain):
        """ d """
        self.policy_published.domain = _sanitize_input(domain)

    def set_policy_adkim(self, adkim):
        """ d """
        self.policy_published.adkim = _sanitize_input(adkim)

    def set_policy_aspf(self, aspf):
        """ d """
        self.policy_published.aspf = _sanitize_input(aspf)

    # pylint: disable-next=invalid-name
    def set_policy_p(self, p):
        """ d """
        self.policy_published.p = _sanitize_input(p)

    # pylint: disable-next=invalid-name
    def set_policy_sp(self, sp):
        """ d """
        self.policy_published.sp = _sanitize_input(sp)

    def set_policy_pct(self, pct):
        """ d """
        self.policy_published.pct = _sanitize_input(pct)

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
                "policy_published": {**asdict(self.policy_published)},
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
    original_envelope_id: list = None
    original_mail_from: str = None
    original_rcpt_to: list = None
    reported_domain: str = None
    reported_uri: list = None
    reporting_mta: dict = None
    source_ip: str = None
    user_agent: str = None
    version: int = None

@dataclass
# pylint: disable-next=too-many-instance-attributes
class ForensicSampleData:
    """ s """
    from_address: str = None
    authentication_results: str = None
    date: datetime = None
    dkim_signature: str = None
    from_address: str = None
    message_id: str = None
    reply_to_address: str = None
    received: list = None
    to_addresses: list = None
    subject: str = None

class ForensicReport():
    """
    A forensic report class to organize and validate data.
    """
    def __init__(self):
        self.dict = {}

        self.report_data = ForensicReportData()
        self.sample_data = ForensicSampleData()

    def add_report_data(self, data: ForensicReportData):
        """ s """
        self.report_data = data

    def add_sample_data(self, data: ForensicSampleData):
        """ s """
        self.sample_data = data

    def get_dict(self) -> dict:
        """ d """
        report = asdict(self.report_data)
        sample = asdict(self.sample_data)

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
    for record in root.findall(".//record"):
        # Rows
        rows = []
        for row in record.findall(".//row"):
            ## Source ip
            source_ip = row.find(".//source_ip")
            source_ip = "" if source_ip is None or source_ip.text is None else source_ip.text
            try:
                ip_addr = ip_address(source_ip)
            except ValueError:
                # Ignore row is IP format is invalid
                continue
            source_ip = str(ip_addr)

            ## Record count
            count = row.find(".//count")
            count = 0 if count is None or count.text is None else count.text

            # Row / Policy Evaluated
            ## Disposition
            eval_disposition = row.find(".//policy_evaluated/disposition")
            # pylint: disable-next=line-too-long
            eval_disposition = "" if eval_disposition is None or eval_disposition.text is None else eval_disposition.text

            ## Evaluated DKIM
            eval_dkim = row.find(".//policy_evaluated/dkim")
            eval_dkim = "" if eval_dkim is None or eval_dkim.text is None else eval_dkim.text

            ## Evaluated SPF
            eval_spf = row.find(".//policy_evaluated/spf")
            eval_spf = "" if eval_spf is None or eval_spf is None else eval_spf.text

            rows.append(Row(
                count = count,
                source_ip = source_ip,
                policy_evaluated = PolicyEvaluated(
                    dkim = eval_dkim,
                    disposition = eval_disposition,
                    spf = eval_spf,
                ),
            ))

        # Identifiers
        ## Header-from
        header_from = record.find(".//identifiers/header_from")
        header_from = "" if header_from is None or header_from is None else header_from.text
        ## Envelope From
        envelope_from = record.find(".//identifiers/envelope_from")
        envelope_from = "" if envelope_from is None or envelope_from is None else envelope_from.text
        ## Envelope To
        envelope_to = record.find(".//identifiers/envelope_to")
        envelope_to = "" if envelope_to is None or envelope_to is None else envelope_to.text

        identifiers = Identifiers(
            header_from = header_from,
            envelope_from = envelope_from,
            envelope_to = envelope_to,
        )

        # Auth Results
        ## SPF Domain
        spf_domain = record.find(".//auth_results/spf/domain")
        spf_domain = "" if spf_domain is None or spf_domain.text is None else spf_domain.text
        ## SPF Result
        spf_result = record.find(".//auth_results/spf/result")
        spf_result = "" if spf_result is None or spf_result.text is None else spf_result.text
        ## SPF Scope
        spf_scope = record.find(".//auth_results/spf/scope")
        spf_scope = "" if spf_scope is None or spf_scope.text is None else spf_scope.text

        ## DKIM Domain
        dkim_domain = record.find(".//auth_results/dkim/domain")
        dkim_domain = "" if dkim_domain is None or dkim_domain.text is None else dkim_domain.text
        ## DKIM Selector
        dkim_selector = record.find(".//auth_results/dkim/selector")
        # pylint: disable-next=line-too-long
        dkim_selector = "" if dkim_selector is None or dkim_selector.text is None else dkim_selector.text
        ## DKIM Result
        dkim_result = record.find(".//auth_results/dkim/result")
        # pylint: disable-next=line-too-long
        dkim_result = "" if dkim_result is None or dkim_result.text is None else dkim_result.text
        ## DKIM Human Result
        dkim_human_result = record.find(".//auth_results/dkim/human_result")
        # pylint: disable-next=line-too-long
        dkim_human_result = "" if dkim_human_result is None or dkim_human_result.text is None else dkim_human_result.text

        auth_results = AuthResults(
            spf = SPF(
                domain = spf_domain,
                result = spf_result,
                scope = spf_scope,
            ),
            dkim = DKIM(
                domain = dkim_domain,
                selector = dkim_selector,
                result = dkim_result,
                human_result = dkim_human_result,
            )
        )

        aggregate_report.add_record(
            Record(
                rows=rows,
                identifiers=identifiers,
                auth_results=auth_results
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
            case "auth-failure": # required?
                if forensic_report_data.auth_failure is not None:
                    raise InvalidFormat("Auth-Failure is used multiple times")
                if value not in {"adsp", "bodyhash", "revoked", "signature", "spf"}:
                    raise ValueError("Auth-Failure got an unknown value according to RFC6591")
                forensic_report_data.auth_failure = value
            case "authentication-results":
                # Required, once.
                # Parse with this RFC:
                # https://www.rfc-editor.org/rfc/rfc5451#section-2.2
                if forensic_report_data.authentication_results is not None:
                    raise InvalidFormat("Authentication-Results is used multiple times")
                counter = 1
                while counter > 0:
                    (value, counter) = re.subn('  ', ' ', value)
                forensic_report_data.authentication_results = value
            case "delivery-result": # optional
                if value not in {"delivered", "spam", "policy", "reject", "other"}:
                    value = "other"
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
            case "feedback-type": # required
                if forensic_report_data.feedback_type is not None:
                    raise InvalidFormat("Feedback-type is used multiple times")
                if value not in {"auth-failure", "abuse", "fraud", "viurs", "other"}:
                    value = "other"
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
                name_type, name = value.split(";", 1)
                forensic_report_data.reporting_mta = {
                    "name": name.strip(),
                    "name_type": name_type.strip(),
                }
            case "original-envelope-id": # optional
                original_envelope_id = forensic_report_data.original_envelope_id
                forensic_report_data.original_envelope_id = _add_string(original_envelope_id, value)
            case "original-mail-from": # optional, once
                if forensic_report_data.original_mail_from is not None:
                    raise InvalidFormat("Original-Mail-From is used multiple times")
                name, address = parseaddr(value)
                forensic_report_data.original_mail_from = {
                    "name": name,
                    "address": address,
                }
            case "original-rcpt-to": # optional
                original_rcpt_to = forensic_report_data.original_rcpt_to
                name, address = parseaddr(value)
                forensic_report_data.original_rcpt_to = _add_string(
                    original_rcpt_to,
                    {"name": name, "address": address},
                )
            case "reported-uri": # optional
                reported_uri = forensic_report_data.reported_uri
                forensic_report_data.reported_uri = _add_string(reported_uri, value)
            case "source-ip": # optional, once
                if forensic_report_data.source_ip is not None:
                    raise InvalidFormat("Source-IP is used multiple times")
                try:
                    ip_addr = ip_address(value)
                except ValueError as _error:
                    raise ValueError("Source-IP could not be parsed") from _error
                # Converting to IPv4Address/IPv6Address is only for verification.
                forensic_report_data.source_ip = str(ip_addr)
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
                # Silent ignore unknown key/values
                continue

    forensic_report.add_report_data(forensic_report_data)
    if not forensic_report.is_report_valid():
        raise InvalidForensicReport("Forensic report is missing required fields")

    # Sample
    forensic_sample_data = ForensicSampleData()
    try:
        sample = sample.encode("utf-8") if not isinstance(sample, bytes) else sample
    except (UnicodeDecodeError, AttributeError) as _error:
        # pylint: disable-next=line-too-long
        raise InvalidForensicSample(f"Forensic sample could not be encoded: {str(_error)}") from _error

    sample = message_from_bytes(sample, _class=EmailMessage, policy=policy.default)
    for key, value in sample.items():
        key = key.lower().strip()
        value = value.strip()

        match key:
            case "authentication-results":
                # Parse results with this RFC:
                # https://www.rfc-editor.org/rfc/rfc5451#section-2.2
                if forensic_sample_data.authentication_results is not None:
                    raise InvalidFormat("Authentication results is used multiple times")
                counter = 1
                while counter > 0:
                    (value, counter) = re.subn('  ', ' ', value)
                forensic_sample_data.authentication_results = value
            case "date":
                if forensic_sample_data.date is not None:
                    raise InvalidFormat("Date is used multiple times")
                try:
                    time = parsedate_to_datetime(value)
                except ValueError as _error:
                    raise InvalidTime("Date could not be parsed") from _error
                forensic_sample_data.date = time
            case "dkim-signature":
                if forensic_sample_data.dkim_signature is not None:
                    raise InvalidFormat("DKIM Signature is used multiple times")
                forensic_sample_data.dkim_signature = value
            case "from":
                if forensic_sample_data.from_address is not None:
                    raise InvalidFormat("From is used multiple times")
                name, address = parseaddr(value)
                forensic_sample_data.from_address = {
                    "name": name,
                    "address": address
                }
            case "message-id":
                if forensic_sample_data.message_id is not None:
                    raise InvalidFormat("Message-ID is used multiple times")
                forensic_sample_data.message_id = value
            case "reply-to":
                if forensic_sample_data.reply_to_address is not None:
                    raise InvalidFormat("Reply-To is used multiple times")
                name, address = parseaddr(value)
                forensic_sample_data.reply_to_address = {
                    "name": name,
                    "address": address,
                }
            case "received":
                received = forensic_sample_data.received
                info, time = value.split(";", 1)

                # Parse Received: with this RFC:
                # https://www.rfc-editor.org/rfc/rfc5321#section-4.4
                counter = 1
                while counter > 0:
                    (info, counter) = re.subn('  ', ' ', info)

                forensic_sample_data.received = _add_string(
                    received,
                    info,
                )
            case "to":
                to_addresses = forensic_sample_data.to_addresses
                name, address = parseaddr(value)
                forensic_sample_data.to_addresses = _add_string(
                    to_addresses,
                    {"name": name, "address": address},
                )
            case "subject":
                if forensic_sample_data.subject is not None:
                    raise InvalidFormat("Subject is used multiple times")
                forensic_sample_data.subject = value
            case _:
                # Silent ignore unknown key/values
                continue

    forensic_report.add_sample_data(forensic_sample_data)
    if not forensic_report.is_sample_valid():
        raise InvalidForensicReport("Forensic sample is missing required fields")

    return forensic_report

def _add_string(original: list, new_value: str) -> list:
    """ A simple function to convert a string to list if there are multiple values """
    if isinstance(original, list):
        original.append(new_value)
        return original
    return [new_value]
