#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC parser library """

import logging

import io

from email import message_from_bytes
from email.message import EmailMessage

from base64 import b64decode

from zipfile import ZipFile, BadZipFile
from gzip import GzipFile, BadGzipFile

import xml.etree.ElementTree as elementTree

from .logger import _custom_logger, _unique_logger_id
from .logger import SYSLOG_TO_SCREEN, SYSLOG_TO_FILE

from .report import AggregateReport, ForensicReport
from .report import InvalidOrgName, InvalidTime

class DmarcParser():
    """
    Public functions:
     - read_file(file: str)
     - extract_report_from_zip(data: io.BytesIO) -> dict
     - extract_report_from_gzip(data: io.BytesIO) -> dict
     - extract_report_from_xml(data: bytes) -> dict
     - extract_report_from_eml(data: bytes) -> dict
     - parse_aggregate_report(self, data: str) -> AggregateReport
     - parse_forensic_report(self, data: str) -> ForensicReport

    Private functions:
     - _get_file_data(data: bytes) -> dict
     - _normalize_xml(xml: str) -> str
    """

    ZIP_SIGNATURE = b"\x50\x4B\x03\x04"
    GZIP_SIGNATURE = b"\x1F\x8B"
    XML_SIGNATURE = b"\x3C\x3F\x78\x6D\x6C\x20"

    def __init__(self, debug_level=logging.INFO):
        self.logger_id = _unique_logger_id()
        self.logger = _custom_logger(self.logger_id, debug_level, SYSLOG_TO_SCREEN | SYSLOG_TO_FILE)

    def read_file(self, file: str):
        """ e """
        if not file.exists() or not file.is_file():
            self.logger.debug("File %s could not be accessed", file)
            return
        self.logger.debug("Found file %s", file)
        try:
            open_file = file.open("rb")
        except FileNotFoundError:
            self.logger.debug("Could not find file %s", file)
        else:
            with open_file:
                data = open_file.read()

        xml = self._get_file_data(data)
        if not xml:
            return

        #self.logger.debug("Report-Data: %s", xml)

        report = None
        if "aggregate" in xml:
            try:
                report = self.parse_aggregate_report(xml["aggregate"]["report"])
            except (InvalidOrgName, InvalidTime) as _error:
                self.logger.debug("ERROR: %s", _error)
        elif "forensic" in xml:
            report = self.parse_forensic_report(xml["forensic"])

        if report:
            self.logger.debug(report)

        return

    def extract_report_from_zip(self, data: io.BytesIO) -> dict:
        """
        Unzip the content from bytes.
        
        Input: io.BytesIO
        
        Output: string (xml-data) or None
        
        """
        xml = None
        try:
            zip_file = ZipFile(data)
        except BadZipFile:
            self.logger.debug("Extract ZIP: The data is not ZIP")
            return None

        with zip_file:
            for file in zip_file.namelist():
                try:
                    data = zip_file.open(file, "r")
                except FileNotFoundError:
                    return None
                with data:
                    xml = data.read()
                    break # TODO: Maybe read more than one file inside the zip?
        try:
            xml = xml.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            self.logger.debug("Extract ZIP: Could not decode file")
            xml = None
        else:
            xml = self._normalize_xml(xml)

        return {"aggregate": {"report": xml}}

    def extract_report_from_gzip(self, data: io.BytesIO) -> dict:
        """
        Unzip the content from bytes.
        
        Input: io.BytesIO
        
        Output: string (xml-data) or None
        
        """
        xml = None
        try:
            gzip_file = GzipFile(data)
        except BadGzipFile:
            self.logger.debug("Extract GZIP: The data is not GZIP")
            return None
        except EOFError:
            self.logger.debug("Extract GZIP: Not all data received?")
            return None

        with gzip_file:
            xml = gzip_file.read()

        try:
            xml = xml.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            self.logger.debug("Extract GZIP: Could not decode file")
            xml = None
        else:
            xml = self._normalize_xml(xml)

        return {"aggregate": {"report": xml}}

    def extract_report_from_xml(self, data: bytes) -> dict:
        """
        Tries to extract xml from bytes.
        
        Input: bytes
        
        Output: string (xml-data) or None
        
        """
        xml = None
        if isinstance(data, str):
            xml = data
        else:
            try:
                xml = data.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                self.logger.debug("Extract XML: Could not decode file")
                return None

            xml = self._normalize_xml(xml)

        # Try parsing XML-data. Assume it is an E-mail file if it breaks.
        try:
            elementTree.fromstring(xml)
        except elementTree.ParseError:
            self.logger.debug("Extract XML: Attached file is not a XML")
            return None

        return {"aggregate": {"report": xml}}

    def extract_report_from_eml(self, data: bytes) -> dict:
        """
        Tries to parse the raw text as EML.
        Extracts the attachments and then tries to extract the xml-data.

        Input: bytes

        Output: tuple. report_type, dict (xml)

        """
        output = {}
        report_type = None

        data = data.encode("utf-8") if not isinstance(data, bytes) else data
        msg = message_from_bytes(data, _class=EmailMessage)

        for attachment in msg.iter_attachments():
            #self.logger.debug("Found attachmnet: %s", attachment.get_filename())
            #self.logger.debug("Content-type: %s", attachment.get_content_type())
            #self.logger.debug("Multipart: %s", attachment.is_multipart())

            content_type = attachment.get_content_type()
            payload = attachment.get_payload()

            if isinstance(payload, list):
                # TODO: Assume [0] or loop through?
                payload = payload[0].get_payload()

            file_encoding = attachment.get("content-transfer-encoding")

            if file_encoding and file_encoding.lower() == "base64":
                payload = payload.encode("ascii")
                payload = b64decode(payload)

            if content_type == "message/feedback-report":
                report_type = "forensic"
                if report_type not in output:
                    output[report_type] = {"report": payload}
                else:
                    output[report_type]["report"] =  payload

            elif content_type == "message/rfc822":
                report_type = "forensic"
                if report_type not in output:
                    output[report_type] = {"sample": payload}
                else:
                    output[report_type]["sample"] = payload

            elif content_type.startswith("application/"):
                reports = self._get_file_data(payload)
                for report, payload in reports.items():
                    if not report:
                        continue
                    output[report] = payload

        return output

    def parse_aggregate_report(self, xml: str) -> AggregateReport:
        """
        Parse the aggregate report.
        
        Input: dict {"aggregate": ...}
        
        Output: AggregateReport object        
        """

        report = AggregateReport()
        if isinstance(xml, str):
            try:
                xml = xml.encode("utf-8")
            except UnicodeDecodeError:
                self.logger.debug("Extract XML: Could not decode file")
                return None

        if not xml:
            return None

        tree = elementTree.parse(io.BytesIO(xml))
        root = tree.getroot()
        #self.logger.debug([elem.tag for elem in tree.getroot().iter()])

        # Organization Name
        org_name = root.find("./report_metadata/org_name")
        org_name = "" if org_name is None or org_name.text is None else org_name.text
        report.set_org_name(org_name)

        # Email
        email = root.find("./report_metadata/email")
        email = "" if email is None or email.text is None else email.text
        report.set_email(email)

        # Report ID
        report_id = root.find("./report_metadata/report_id")
        report_id = "" if report_id is None or report_id.text is None else report_id.text
        report.set_report_id(report_id)

        # Start time of the report
        date_begin = root.find("./report_metadata/date_range/begin")
        date_begin = 0 if date_begin is None or date_begin.text is None else date_begin.text
        report.set_date_begin(date_begin)

        # End time of the report
        date_end = root.find("./report_metadata/date_range/end")
        date_end = 0 if date_end is None or date_end is None else date_end.text
        report.set_date_end(date_end)

        # Parse policy_published
        domain = root.find("./policy_published/domain")
        adkim = root.find("./policy_published/adkim")
        aspf = root.find("./policy_published/aspf")
        p = root.find("./policy_published/p")
        sp = root.find("./policy_published/sp")
        pct = root.find("./policy_published/pct")

        print(domain.text)
        print(adkim.text)
        print(aspf.text)
        print(p.text)
        print(sp.text)
        print(pct.text)

        # Parse records
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

        return report

    def parse_forensic_report(self, data: dict) -> ForensicReport:
        """
        Parse the forensic report and sample
        
        Input: dict {"forensic": ..., "sample": ...}
        
        Output: ForensicReport object        
        """
        xml = None
        report = None
        if isinstance(data, str):
            try:
                xml = data.encode("utf-8")
            except UnicodeDecodeError:
                self.logger.debug("Extract XML: Could not decode file")
                return None

        if not xml:
            return None

        return report

    def _get_file_data(self, data: bytes) -> dict:
        """ Guesses the signature and then extract xml-data """
        if data.startswith(self.ZIP_SIGNATURE):
            xml = self.extract_report_from_zip(io.BytesIO(data))
        elif data.startswith(self.GZIP_SIGNATURE):
            xml = self.extract_report_from_gzip(io.BytesIO(data))
        elif data.lstrip().startswith(self.XML_SIGNATURE):
            xml = self.extract_report_from_xml(data)
        else:
            xml = self.extract_report_from_eml(data)
        return xml

    def _normalize_xml(self, xml: str) -> str:
        """ Normalize the xml. Remove newlines and strip white spaces """
        return "".join(s.strip() for s in xml.splitlines())
