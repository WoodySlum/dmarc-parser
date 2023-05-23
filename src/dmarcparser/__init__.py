#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This is a DMARC parser library """

import logging
import os
import io
from datetime import datetime

from email import message_from_bytes
from email.message import EmailMessage

from base64 import b64decode

import html

from zipfile import ZipFile, BadZipFile
from gzip import GzipFile, BadGzipFile
from pathlib import Path
import xml.etree.ElementTree as elementTree

from .logger import _custom_logger
from .logger import SYSLOG_TO_SCREEN, SYSLOG_TO_FILE

ZIP_SIGNATURE = b"\x50\x4B\x03\x04"
GZIP_SIGNATURE = b"\x1F\x8B"
XML_SIGNATURE = b"\x3C\x3F\x78\x6D\x6C\x20"

class Parser():
    """ h """
    def __init__(self, debug_level=logging.INFO):
        self.logger = _custom_logger("dmarcparser", debug_level, SYSLOG_TO_SCREEN | SYSLOG_TO_FILE)

    def normalize_xml(self, xml: str) -> str:
        """ Normalize the xml. Remove newlines and strip white spaces """
        return "".join(s.strip() for s in xml.splitlines())

    def extract_zip(self, data: io.BytesIO) -> str:
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
            xml = self.normalize_xml(xml)

        return xml

    def extract_gzip(self, data: io.BytesIO) -> str:
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
            xml = self.normalize_xml(xml)

        return xml

    def extract_xml(self, data: bytes) -> str:
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

            xml = self.normalize_xml(xml)

        # Try parsing XML-data. Assume it is an E-mail file if it breaks.
        try:
            elementTree.fromstring(xml)
        except elementTree.ParseError:
            self.logger.debug("Extract XML: Attached file is not a XML")
            return None

        return xml

    def _read_eml(self, data: bytes) -> str:
        """
        Tries to parse the raw text as EML.
        Extracts the attachments and then tries to extract the xml-data.

        Input: bytes

        Output: string (xml-data) or None

        """
        xml = None
        if not isinstance(data, bytes):
            xml = data.encode("utf-8")
        msg = message_from_bytes(data, _class=EmailMessage)
        for attachment in msg.iter_attachments():
            self.logger.debug("Found attachmnet: %s", attachment.get_filename())
            file_data = attachment.get_payload()
            file_encoding = attachment.get("content-transfer-encoding")

            # Get binary data from attachment
            if file_encoding.lower() == "base64":
                file_data = file_data.encode("ascii")
                file_data = b64decode(file_data)
            else:
                self.logger.debug("Unknown encoding: %s", file_encoding)
                continue

            # Extract xml
            xml = self._get_file_data(file_data)

            # Break the loop if XML data is found
            if xml:
                break

        return xml

    def _get_file_data(self, data: bytes) -> str:
        """ Guesses the signature and then extract xml-data """
        if data.startswith(ZIP_SIGNATURE):
            xml = self.extract_zip(io.BytesIO(data))
        elif data.startswith(GZIP_SIGNATURE):
            xml = self.extract_gzip(io.BytesIO(data))
        elif data.lstrip().startswith(XML_SIGNATURE):
            xml = self.extract_xml(data)
        else:
            xml = None
        return xml

    def _read_files(self, files: list = None) -> dict:
        if files is None:
            files = []
        xml_data = {}
        for file in files:
            xml = None
            # Check if the file variable actually exist and is a file
            if not file.exists() or not file.is_file():
                self.logger.debug("File %s could not be accessed", file)
                continue
            # Get filetype by reading the signature / magic bytes
            self.logger.debug("Found file %s", file)
            try:
                open_file = file.open("rb")
            except FileNotFoundError:
                self.logger.debug("Could not find file %s", file)
            else:
                with open_file:
                    data = open_file.read()
                    xml = self._get_file_data(data)

                    # If xml is empty, try parsing 'raw' text as an EML-file
                    if not xml:
                        xml = self._read_eml(data)
            if not xml:
                continue

            xml_data[str(file)] = xml

        return xml_data

    def _sanitize_input(self, string: str) -> str:
        """ Sanitize a string to not wreak havoc """
        return html.escape(string)

    def parse_report(self, data: bytes) -> dict:
        """ D """
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

        self.logger.debug("XML: %s", xml)
        tree = elementTree.parse(io.BytesIO(xml))
        root = tree.getroot()
        #self.logger.debug([elem.tag for elem in tree.getroot().iter()])

        # Organization Name
        org_name = root.find("./report_metadata/org_name")
        if org_name is None or org_name.text is None:
            org_name = ""
        else:
            org_name = org_name.text
        if len(org_name) < 1:
            self.logger.debug("Empty org name")
        org_name = self._sanitize_input(org_name)

        # Email
        email = root.find("./report_metadata/email")
        if email is None or email.text is None:
            email = ""
        else:
            email = email.text
        if len(email) < 1:
            self.logger.debug("Empty email")
        email = self._sanitize_input(email)

        # Report ID
        report_id = root.find("./report_metadata/report_id")
        if report_id is None or report_id.text is None:
            report_id = 0
        else:
            report_id = report_id.text
        if len(report_id) < 1:
            self.logger.debug("Empty report-id")
        report_id = self._sanitize_input(report_id)

        # Start time of the report
        date_begin = root.find("./report_metadata/date_range/begin")
        if date_begin is None or date_begin.text is None:
            date_begin = elementTree.Element(0)
        else:
            date_begin = date_begin.text
            if not isinstance(date_begin, int):
                try:
                    date_begin = int(date_begin)
                except ValueError:
                    date_begin = 0
                    self.logger.debug("Date begin is not a number")
        if date_begin < 1:
            self.logger.debug("Empty date begin")
        self.logger.debug("Time Begin: %s", datetime.fromtimestamp(date_begin))

        # End time of the report
        date_end = root.find("./report_metadata/date_range/end")
        if date_end is None or date_end is None:
            date_end = elementTree.Element(0)
        else:
            date_end = date_end.text
            if not isinstance(date_end, int):
                try:
                    date_end = int(date_end)
                except ValueError:
                    date_begin = 0
                    self.logger.debug("Date end is not a number")
        if date_end < 1:
            self.logger.debug("Empty date end")
        self.logger.debug("Time End: %s", datetime.fromtimestamp(date_end))

        self.logger.debug("%s %s %s %s %s", org_name, email, report_id, date_begin, date_end)
        return report

    def parsefolder(self, folder, recursive=False):
        """ Parse a folder """
        if not os.path.exists(folder):
            self.logger.debug("%s do not exist", folder)
            return
        if not os.path.isdir(folder):
            self.logger.debug("%s is not a folder", folder)
            return
        xmls = {}
        if recursive:
            files_found = []
            for root, _, files in os.walk(folder):
                files_found.extend([Path(root) / f for f in files])
            xmls = self._read_files(files_found)
        else:
            for file in [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]:
                self.logger.debug("Not recursive!!")
                self.logger.debug(file)
        for filename, xml in xmls.items():
            self.logger.debug("Filename: %s, Report: %s", filename, self.parse_report(xml))

    def parsefile(self, file):
        """ Parse a file """
        if not os.path.exists(file):
            self.logger.debug("%s do not exist", file)
            return
        if not os.path.isfile(file):
            self.logger.debug("%s is not a file", file)
            return
        self._read_files([Path(file)])
