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

from .report import aggregate_report_from_xml, forensic_report_from_xml
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

        report = self._get_file_data(data)
        if not report:
            return

        #self.logger.debug("Report-Data: %s", xml)

        output = None
        if "aggregate" in report:
            try:
                output = self.parse_aggregate_report(report)
            except (InvalidOrgName, InvalidTime) as _error:
                self.logger.debug("ERROR: %s", _error)
        elif "forensic" in report:
            output = self.parse_forensic_report(report)

        if output:
            self.logger.debug(output)

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
                    # Should never be more than one file so lets break.
                    break
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
        # pylint: disable=too-many-branches
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
                # Since we iter through attachments, we could get away with assuming [0].
                # Might regret this.
                payload = payload[0].get_payload()
            else:
                payload = payload.get_payload()

            file_encoding = attachment.get("content-transfer-encoding")

            if file_encoding and file_encoding.lower() == "base64":
                payload = payload.encode("ascii")
                payload = b64decode(payload)

            if content_type == "message/feedback-report":
                report_type = "forensic"

                try:
                    payload = payload.decode("utf-8") if isinstance(payload, bytes) else payload
                except UnicodeDecodeError:
                    self.logger.debug("message/feedback-report could not be decoded to UTF-8")
                    continue

                if report_type not in output:
                    output[report_type] = {"report": payload}
                else:
                    output[report_type]["report"] =  payload

            elif content_type == "message/rfc822":
                report_type = "forensic"

                try:
                    payload = payload.decode("utf-8") if isinstance(payload, bytes) else payload
                except UnicodeDecodeError:
                    self.logger.debug("message/rfc822 could not be decoded to UTF-8")
                    continue

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
        if output:
            self.logger.debug(output)
        return output

    def parse_aggregate_report(self, report: dict) -> AggregateReport:
        """
        Parse the aggregate report.
        
        Input: dict {"aggregate": {"report": ...}}
        
        Output: AggregateReport object        
        """

        if "aggregate" not in report and "report" in report["aggregate"]:
            return None

        xml = report["aggregate"]["report"]

        if isinstance(xml, str):
            try:
                xml = xml.encode("utf-8")
            except UnicodeDecodeError:
                self.logger.debug("Extract XML: Could not decode file")
                return None

        if not xml:
            return None

        return aggregate_report_from_xml(xml)

    def parse_forensic_report(self, report: dict) -> ForensicReport:
        """
        Parse the forensic report and sample
        
        Input: dict {"forensic": {"report": ..., "sample": ...}}
        
        Output: ForensicReport object        
        """

        if "forensic" not in report and "report" in report["forensic"]:
            return None

        return forensic_report_from_xml(report["forensic"]["report"], report["forensic"]["sample"])

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
