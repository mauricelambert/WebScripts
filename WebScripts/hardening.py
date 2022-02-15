#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool run scripts and display the result in a Web Interface.
#    Copyright (C) 2021, 2022  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This tool run scripts and display the result in a Web Interface.

This file implement the hardening audit of the WebScripts installation and
configuration.
"""

__version__ = "1.1.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file implement the hardening audit of the WebScripts installation and
configuration.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Report", "Rule", "Audit", "SEVERITY", "main"]

from os.path import (
    exists,
    join,
    isdir,
    split,
    dirname,
    basename,
    isfile,
    isabs,
)
from os import getcwd, listdir, stat, stat_result, scandir
from sys import prefix, base_prefix, modules, executable
from typing import TypeVar, List, Set, Dict, Tuple
from time import sleep, strftime, localtime
from io import open, DEFAULT_BUFFER_SIZE
from email.message import EmailMessage
from collections.abc import Callable
from collections.abc import Iterator
from json import load, dumps, loads
from smtplib import SMTP, SMTP_SSL
from urllib.request import urlopen
from hashlib import new as newhash
from tempfile import TemporaryFile
from urllib.error import URLError
from dataclasses import dataclass
from zipimport import zipimporter
from socket import gethostbyname
from pkgutil import iter_modules
from contextlib import suppress
from operator import itemgetter
from shutil import copyfileobj
from types import ModuleType
from threading import Thread
from getpass import getuser
from platform import system
from stat import filemode
from enum import Enum
from glob import glob
import ctypes
import os

try:
    import pip._internal.operations.freeze
except (ImportError, AttributeError):
    PIP = False
else:
    PIP = True

ServerConfiguration = TypeVar("ServerConfiguration")
Server = TypeVar("Server")
Logs = TypeVar("Logs")
server_path = dirname(__file__)


class SEVERITY(Enum):

    """
    Severity level of the rules.
    """

    INFORMATION = "INFORMATION"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GETTER:

    """
    This class groups getters.
    """

    sever = itemgetter("severity")
    score = itemgetter("SCORING")
    field = itemgetter("fields")
    total = itemgetter("total")
    fail = itemgetter("FAIL")
    info = itemgetter(SEVERITY.INFORMATION.value)
    crit = itemgetter(SEVERITY.CRITICAL.value)
    med = itemgetter(SEVERITY.MEDIUM.value)
    high = itemgetter(SEVERITY.HIGH.value)
    low = itemgetter(SEVERITY.LOW.value)


@dataclass
class Rule:

    """
    This class implement a rule for hardening.
    """

    subject: str
    id_: int
    is_OK: bool
    level: int
    severity: str
    category: str
    reason: str


class Report:

    """
    This class implement the report object.
    """

    def __init__(
        self,
        rules: List[Rule],
        file_integrity: List[Dict[str, str]],
        server: Server,
        logs: Logs,
    ):
        self.rules = rules
        self.server = server
        self.logs = logs
        self.reports_json: str = None
        self.reports_dict: str = None
        self.reports_text: str = None
        self.reports_html: str = None
        self.file_integrity = file_integrity

    @staticmethod
    def truncate_string(
        string: str, length: int = 13, end: str = "...", separator: str = ","
    ) -> str:

        """
        This function truncate a string.
        """

        if not isinstance(string, str):
            string = str(string)

        length_string = len(string)

        if length_string > 13:
            string = f"{string[:length - len(end)]}{end}{separator}"
        else:
            string = f"{string}{separator}{' ' * (length - length_string)}"

        return string

    def as_json(self) -> str:

        """
        This function returns a JSON string of audit results.
        """

        G = GETTER

        scoring = {f"{s.value} total": 0 for s in SEVERITY}
        scoring.update({f"{s.value} fail": 0 for s in SEVERITY})

        scoring["total"] = 0
        scoring["FAIL"] = 0

        self.reports_dict = {
            SEVERITY.INFORMATION.value: [],
            SEVERITY.LOW.value: [],
            SEVERITY.MEDIUM.value: [],
            SEVERITY.HIGH.value: [],
            SEVERITY.CRITICAL.value: [],
            "FAIL": [],
            "ALL": [],
            "SCORING": scoring,
            "fields": [],
            "file integrity": self.file_integrity,
        }

        for rule in self.rules:

            audit = {}
            self.reports_dict["ALL"].append(audit)
            self.reports_dict[rule.severity].append(audit)
            scoring["total"] += rule.level
            scoring[f"{rule.severity} total"] += rule.level

            if not rule.is_OK:
                G.fail(self.reports_dict).append(audit)
                scoring["FAIL"] += rule.level
                scoring[f"{rule.severity} fail"] += rule.level

            for attribut in Rule.__dataclass_fields__.keys():

                if attribut == "is_OK":
                    new_attribut = "state"
                    new_value = "PASS" if getattr(rule, attribut) else "FAIL"
                elif attribut == "id_":
                    new_attribut = "ID"
                    new_value = getattr(rule, attribut)
                else:
                    new_attribut = attribut
                    new_value = getattr(rule, attribut)

                if new_attribut not in G.field(self.reports_dict):
                    G.field(self.reports_dict).append(new_attribut)

                audit[new_attribut] = new_value

        def sort(rule: dict) -> int:
            return rule["level"]

        self.reports_dict["ALL"] = sorted(
            self.reports_dict["ALL"], key=sort, reverse=True
        )
        self.reports_dict["FAIL"] = sorted(
            G.fail(self.reports_dict), key=sort, reverse=True
        )

        fields = self.reports_dict.pop("fields")
        self.reports_json = dumps(self.reports_dict, indent=4)
        self.reports_dict["fields"] = fields

        return self.reports_json

    def get_pourcent(self) -> None:

        """
        This function calcul pourcent.
        """

        scoring = GETTER.score(self.reports_dict)

        self.pourcent = {
            s.value: 100
            - scoring[f"{s.value} fail"] * 100 / scoring[f"{s.value} total"]
            for s in SEVERITY
        }
        self.pourcent["ALL"] = 100 - GETTER.fail(scoring) * 100 / GETTER.total(
            scoring
        )

    @staticmethod
    def get_HTML_table(headers: str, rules: List[Rule]) -> str:

        """
        This function returns a HTML table with rule attributes as columns.
        """

        table = headers
        for rule in rules:
            class_ = f'class="{GETTER.sever(rule).lower()}"'
            table += (
                f"<tr><td {class_}>"
                + f"</td><td {class_}>".join(str(x) for x in rule.values())
                + "</td></tr>"
            )
        return table

    def as_html(self) -> str:

        """This function return a HTML string of audit results."""

        G = GETTER
        scoring = G.score(self.reports_dict)
        get_HTML_table = self.get_HTML_table

        if self.reports_dict is None:
            self.as_json()

        table = (
            f"<tr><td>{'</td><td>'.join(G.field(self.reports_dict))}"
            "</td></tr>"
        )

        table_fail = get_HTML_table(table, G.fail(self.reports_dict))
        table_critical = get_HTML_table(table, G.crit(self.reports_dict))
        table_high = get_HTML_table(table, G.high(self.reports_dict))
        table_medium = get_HTML_table(table, G.med(self.reports_dict))
        table_low = get_HTML_table(table, G.low(self.reports_dict))
        table_information = get_HTML_table(table, G.info(self.reports_dict))

        file_integrity = self.file_integrity
        score_integrity = sum([x["Score"] for x in file_integrity])
        failed_integrity = len(file_integrity)

        for integrity in file_integrity:
            if integrity["Score"] == 10:
                integrity["severity"] = "CRITICAL"
            elif integrity["Score"] >= 5:
                integrity["severity"] = "HIGH"
            else:
                integrity["severity"] = "MEDIUM"

        if file_integrity:
            table = (
                f"<tr><td>{'</td><td>'.join(file_integrity[0].keys())}"
                "</td></tr>"
            )
            table_integrity = get_HTML_table(table, file_integrity)
        else:
            table_integrity = (
                '<p class="information">No compromised files.</p>'
            )

        self.reports_html = f"""
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>WebScripts audit</title>
        <style type="text/css">
            html, body {{width: 100%; background-color: #222222;}}
            h1 {{text-align: center;}}
            h1, h2, p, table, tr, td, li, ul, a {{
                color: #ffc26a;
                font-family : Arial, Helvetica, "Liberation Sans",
                FreeSans, sans-serif;
            }}
            tr, td {{
                margin: 0.5%;
                padding: 1%;
                padding-left: 0.1%;
                color: #b16b05;
                border: 1px solid #b16b05;
            }}
            table {{width: 99%; background-color: #CCCCCC; color: #b16b05;}}
            .critical {{color: #B13D05; border: 1px solid #B13D05;}}
            .high {{color: #dd8a12; border: 1px solid #dd8a12;}}
            .medium {{color: #B18905; border: 1px solid #B18905;}}
            .low {{color: #100B60; border: 1px solid #100B60;}}
            .information {{color: #04774E; border: 1px solid #04774E;}}
            .integrity {{background-color: #CCCCCC; color: #B13D05;}}
        </style>
    </head>
    <body>
        <h1>WebScripts: Hardening Audit Report</h1>

        <h2>Links</h2>
        <ul>
            <li><a href="#integrity_score">Integrity Score</a></li>
            <li><a href="#scoring">Scoring</a></li>
            <li><a href="#failed">Failed</a></li>
            <li><a href="#integrity_report">Integrity Report</a></li>
            <li><a href="#critical">Critical</a></li>
            <li><a href="#high">High</a></li>
            <li><a href="#medium">Medium</a></li>
            <li><a href="#low">Low</a></li>
            <li><a href="#information">Information</a></li>
        </ul>

        <h2 id="integrity_score">INTEGRITY</h2>

        <p class="integrity"><strong>File number</strong>: {failed_integrity}
        (file should be 0)<br>
        <strong>Score</strong>: {score_integrity} (score should be 0)<br></p>

        <h2 id="scoring">SCORING</h2>
        <table>
            <tr>
                <td>Score</td>
                <td>Fail</td>
                <td>Total</td>
                <td>Compliance (% pourcent)</td>
            </tr>
            <tr>
                <td>All</td>
                <td>{G.fail(scoring)}</td>
                <td>{G.total(scoring)}</td>
                <td>
{self.pourcent['ALL']}
                </td>
            </tr>
            <tr>
                <td class="critical">Critical</td>
                <td class="critical">
{scoring[f"{SEVERITY.CRITICAL.value} fail"]}
                </td>
                <td class="critical">
{scoring[f"{SEVERITY.CRITICAL.value} total"]}
                </td><td class="critical">
{G.crit(self.pourcent)}
                </td>
            </tr>
            <tr>
                <td class="high">High</td>
                <td class="high">
{scoring[f"{SEVERITY.HIGH.value} fail"]}
                </td>
                <td class="high">
{scoring[f"{SEVERITY.HIGH.value} total"]}
                </td>
                <td class="high">
{G.high(self.pourcent)}
                </td>
            </tr>
            <tr>
                <td class="medium">Medium</td>
                <td class="medium">
{scoring[f"{SEVERITY.MEDIUM.value} fail"]}
                </td>
                <td class="medium">
{scoring[f"{SEVERITY.MEDIUM.value} total"]}
                </td>
                <td class="medium">
{G.med(self.pourcent)}
                </td>
            </tr>
            <tr>
                <td class="low">Low</td>
                <td class="low">
{scoring[f"{SEVERITY.LOW.value} fail"]}
                </td>
                <td class="low">
{scoring[f"{SEVERITY.LOW.value} total"]}
                </td>
                <td class="low">
{G.low(self.pourcent)}
                </td>
            </tr>
            <tr>
                <td class="information">Information</td>
                <td class="information">
{scoring[f"{SEVERITY.INFORMATION.value} fail"]}
                </td>
                <td class="information">
{scoring[f"{SEVERITY.INFORMATION.value} total"]}
                </td>
                <td class="information">
{G.info(self.pourcent)}
                </td>
            </tr>
        </table>

        <h2 id="failed">FAILED</h2>
        <table>
            {table_fail}
        </table>

        <h2 id="integrity_report">INTEGRITY</h2>

        <table>
            {table_integrity}
        </table>

        <h2 id="critical">CRITICAL</h2>
        <table>
            {table_critical}
        </table>

        <h2 id="high">HIGH</h2>
        <table>
            {table_high}
        </table>

        <h2 id="medium">MEDIUM</h2>
        <table>
            {table_medium}
        </table>

        <h2 id="low">LOW</h2>
        <table>
            {table_low}
        </table>

        <h2 id="information">INFORMATION</h2>
        <table>
            {table_information}
        </table>

    </body>
</html>
        """

        return self.reports_html

    @staticmethod
    def get_text_table(
        headers: str, rules: List[Rule], joiner: str = "    "
    ) -> str:

        """
        This function return a text table with rule attributes as columns.
        """

        return headers + "\n    - ".join(
            [
                joiner.join(
                    f"{Report.truncate_string(value)}"
                    for value in rule.values()
                )
                for rule in rules
            ]
        )

    def as_text(self) -> str:

        """This function return a HTML string of audit results."""

        if self.reports_dict is None:
            self.as_json()

        G = GETTER
        scoring = G.score(self.reports_dict)
        tab = "  "
        # end = "..."

        headers = tab.join(
            self.truncate_string(f) for f in Rule.__dataclass_fields__.keys()
        )
        headers = f"    ~ {headers}\n    - "

        fail_text = self.get_text_table(
            headers, G.fail(self.reports_dict), tab
        )
        critical_text = self.get_text_table(
            headers, G.crit(self.reports_dict), tab
        )
        high_text = self.get_text_table(
            headers, G.high(self.reports_dict), tab
        )
        medium_text = self.get_text_table(
            headers, G.med(self.reports_dict), tab
        )
        low_text = self.get_text_table(headers, G.med(self.reports_dict), tab)
        information_text = self.get_text_table(
            headers, G.info(self.reports_dict), tab
        )

        self.reports_text = f"""
     ___________________________________________
    |                                           |
    |  ** WebScripts Hardening Audit Report **  |
    |___________________________________________|

 1. Scoring
    - ALL:         Total:\t{G.total(scoring):0>4},\
  Fail:\t{G.fail(scoring):0>4},  Pourcent:\t\
{self.pourcent['ALL']:0>3}%
    - CRITICAL:    Total:\t\
{scoring[f"{SEVERITY.CRITICAL.value} total"]:0>4},  Fail:\t\
{scoring[f"{SEVERITY.CRITICAL.value} fail"]:0>4},  \
Pourcent:\t{G.crit(self.pourcent):0>3}%
    - HIGH:        Total:\t\
{scoring[f"{SEVERITY.HIGH.value} total"]:0>4},  Fail:\t\
{scoring[f"{SEVERITY.HIGH.value} fail"]:0>4},  Pourcent:\t\
{G.high(self.pourcent):0>3}%
    - MEDIUM:      Total:\t\
{scoring[f"{SEVERITY.MEDIUM.value} total"]:0>4},  Fail:\t\
{scoring[f"{SEVERITY.MEDIUM.value} fail"]:0>4},  Pourcent:\
\t{G.med(self.pourcent):0>3}%
    - LOW:         Total:\t\
{scoring[f"{SEVERITY.LOW.value} total"]:0>4},  Fail:\t\
{scoring[f"{SEVERITY.LOW.value} fail"]:0>4},  Pourcent:\t\
{G.low(self.pourcent):0>3}%
    - INFORMATION: Total:\t{
scoring[f"{SEVERITY.INFORMATION.value} total"]:0>4},  Fail:\
\t{scoring[f"{SEVERITY.INFORMATION.value} fail"]:0>4}, \
 Pourcent:\t{G.info(self.pourcent):0>3}%

 2. Failed
{fail_text}

 3. Critical
{critical_text}

 4. High
{high_text}

 5. Medium
{medium_text}

 6. Low
{low_text}

 7. Information
{information_text}
        """

        return self.reports_text

    def notification(self) -> None:

        """
        This function send an email notification
        to administrator with the audit report.
        """

        if self.reports_text is None:
            self.as_text()

        server_name = getattr(self.server.configuration, "smtp_server", None)
        starttls = getattr(self.server.configuration, "smtp_starttls", None)
        password = getattr(self.server.configuration, "smtp_password", None)

        if not server_name:
            return

        sleep(
            60
        )  # Wait 1 minutes (else "SmtpError: to many connections" is raised)

        try:
            if starttls:
                server = SMTP(
                    server_name,
                    getattr(self.server.configuration, "smtp_port", 587),
                )
            elif getattr(self.server.configuration, "smtp_ssl", None):
                server = SMTP_SSL(
                    server_name,
                    getattr(self.server.configuration, "smtp_port", 465),
                )
            else:
                server = SMTP(
                    server_name,
                    getattr(self.server.configuration, "smtp_port", 25),
                )
        except TimeoutError:
            self.logs.error("Connection error with SMTP server")
            return

        if password:
            server.login(self.server.configuration.email, password)

        msg = EmailMessage()
        msg.set_content(
            '<html><head><meta charset="utf-8">'
            "<title>WebScripts Hardening Report</title></head><body><pre>"
            f"<code>{self.reports_text}</code></pre></body></html>"
        )
        msg.replace_header("Content-Type", "text/html; charset=utf-8")

        msg["From"] = self.server.configuration.notification_address
        msg["To"] = ", ".join(self.server.configuration.admin_adresses)
        msg["Subject"] = "[! WebScripts Hardening Report ]"

        if self.reports_html is not None:
            msg.add_attachment(
                self.reports_html.encode(),
                maintype="text",
                subtype="html",
                filename="audit.html",
            )

        if self.reports_json is not None:
            msg.add_attachment(
                self.reports_json.encode(),
                maintype="application",
                subtype="json",
                filename="audit.json",
            )

        server.send_message(msg)
        server.quit()


class Audit:

    """
    This function implement hardening checks.
    """

    is_windows = system() == "Windows"
    current_dir = getcwd()
    network_up = True
    latest_ = []
    latest = []

    def audit_in_venv(server: Server) -> Rule:

        """
        This function checks the virtualenv.
        """

        return Rule(
            "Virtualenv",
            0,
            prefix != base_prefix,
            3,
            SEVERITY.LOW.value,
            "Installation",
            "WebScripts is not install in virtualenv.",
        )

    def audit_config_files(server: Server) -> Rule:

        """
        This function checks the configurations files.
        """

        files = [
            join("config", "server.ini"),
            join("config", "server.json"),
            join(server_path, "config", "nt", "server.ini")
            if Audit.is_windows
            else join(server_path, "config", "server.ini"),
            join(server_path, "config", "nt", "server.json")
            if Audit.is_windows
            else join(server_path, "config", "server.json"),
        ]
        compteur = 0

        for file in files:
            if isfile(file):
                compteur += 1

        return Rule(
            "Configurations files",
            31,
            compteur <= 1,
            5,
            SEVERITY.MEDIUM.value,
            "Installation",
            "WebScripts should be configured by only one configuration file.",
        )

    def audit_venv_modules(server: Server) -> Rule:

        """
        This function checks the virtualenv modules.
        """

        venv_modules = []

        if PIP and Audit.is_windows:
            modules = [
                package
                for package in pip._internal.operations.freeze.freeze()
                if not package.startswith("pip==")
                and not package.startswith("setuptools==")
                and not package.startswith("pywin32==")
                and not package.startswith("WebScripts==")
                and not package.startswith("pkg-resources==")
            ]
            return Rule(
                "Virtualenv modules",
                32,
                len(modules) == 0,
                3,
                SEVERITY.LOW.value,
                "Installation",
                "WebScripts should be install in empty virtualenv (except "
                f"pywin32 on Windows), modules found: {modules}.",
            )
        elif PIP and not Audit.is_windows:
            modules = [
                package
                for package in pip._internal.operations.freeze.freeze()
                if not package.startswith("pip==")
                and not package.startswith("setuptools==")
                and not package.startswith("WebScripts==")
                and not package.startswith("pkg-resources==")
            ]
            return Rule(
                "Virtualenv modules",
                32,
                len(modules) == 0,
                3,
                SEVERITY.LOW.value,
                "Installation",
                "WebScripts should be install in empty virtualenv (except "
                f"pywin32 on Windows), modules found: {modules}.",
            )

        if Audit.is_windows:
            preinstall_modules = [
                "WebScripts-script",
                "activate_this",
                "pywin32_postinstall",
                "pywin32_testall",
                "wsgi",
                "WebScripts",
                "adodbapi",
                "easy_install",
                "isapi",
                "pip",
                "pkg_resources",
                "pythoncom",
                "setuptools",
                "win32com",
                "_win32sysloader",
                "_winxptheme",
                "mmapfile",
                "odbc",
                "perfmon",
                "servicemanager",
                "timer",
                "win2kras",
                "win32api",
                "win32clipboard",
                "win32console",
                "win32cred",
                "win32crypt",
                "win32event",
                "win32evtlog",
                "win32file",
                "win32gui",
                "win32help",
                "win32inet",
                "win32job",
                "win32lz",
                "win32net",
                "win32pdh",
                "win32pipe",
                "win32print",
                "win32process",
                "win32profile",
                "win32ras",
                "win32security",
                "win32service",
                "win32trace",
                "win32transaction",
                "win32ts",
                "win32wnet",
                "winxpgui",
                "afxres",
                "commctrl",
                "dbi",
                "mmsystem",
                "netbios",
                "ntsecuritycon",
                "pywin32_bootstrap",
                "pywin32_testutil",
                "pywintypes",
                "rasutil",
                "regcheck",
                "regutil",
                "sspi",
                "sspicon",
                "win32con",
                "win32cryptcon",
                "win32evtlogutil",
                "win32gui_struct",
                "win32inetcon",
                "win32netcon",
                "win32pdhquery",
                "win32pdhutil",
                "win32rcparser",
                "win32serviceutil",
                "win32timezone",
                "win32traceutil",
                "win32verstamp",
                "winerror",
                "winioctlcon",
                "winnt",
                "winperf",
                "winxptheme",
                "dde",
                "pywin",
                "win32ui",
                "win32uiole",
                "uploads_management",
            ]
        else:
            preinstall_modules = [
                "easy_install",
                "pip",
                "pkg_resources",
                "setuptools",
                "WebScripts",
                "activate_this",
                "wsgi",
                "distutils",
                "uploads_management",
            ]

        for module in iter_modules():
            finder = module.module_finder

            if (
                isinstance(finder, zipimporter)
                and finder.archive.startswith(prefix)
                and not [
                    m
                    for m in preinstall_modules
                    if m in basename(finder.archive)
                ]
            ):
                venv_modules.append(basename(finder.archive))
            elif isinstance(finder, zipimporter):
                continue
            elif finder.path.startswith(prefix) and not [
                m for m in preinstall_modules if m in module.name
            ]:
                venv_modules.append(module.name)

        return Rule(
            "Virtualenv modules",
            32,
            len(venv_modules) == 0,
            3,
            SEVERITY.LOW.value,
            "Installation",
            "WebScripts should be install in empty virtualenv (except "
            f"pywin32 on Windows), modules found: {venv_modules}.",
        )

    def audit_system_user(server: Server) -> Rule:

        """
        This function checks the user.
        """

        if Audit.is_windows:
            is_admin = not ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = os.getuid()

        return Rule(
            "System user",
            1,
            is_admin,
            9,
            SEVERITY.CRITICAL.value,
            "Process",
            "WebScripts is launch with admin rights.",
        )

    def audit_interface(server: Server) -> Rule:

        """
        This function checks the network interface.
        """

        return Rule(
            "Network Interface",
            2,
            gethostbyname(server.interface) == "127.0.0.1",
            9,
            SEVERITY.CRITICAL.value,
            "Configuration",
            "Server interface is not 127.0.0.1.",
        )

    def audit_force_auth(server: Server) -> Rule:

        """This function checks authentication is forced."""

        return Rule(
            "Force authentication",
            14,
            not server.configuration.accept_unauthenticated_user
            and not server.configuration.accept_unknow_user,
            5,
            SEVERITY.MEDIUM.value,
            "Configuration",
            "Authentication is not forced.",
        )

    def audit_active_auth(server: Server) -> Rule:

        """
        This function checks authentication is enabled.
        """

        return Rule(
            "Active authentication",
            15,
            server.configuration.active_auth
            and server.configuration.auth_script is not None,
            7,
            SEVERITY.HIGH.value,
            "Configuration",
            "Authentication is disabled.",
        )

    def audit_limit_exclude_auth(server: Server) -> Rule:

        """
        This function checks exclusions for authentication.
        """

        limit_exclusion = True

        for path_ in server.configuration.exclude_auth_paths:
            if path_ not in ["/static/", "/js/"]:
                limit_exclusion = False

        for page in server.configuration.exclude_auth_pages:
            if page not in ["/api/", "/auth/", "/web/auth/"]:
                limit_exclusion = False

        return Rule(
            "Authentication exclusions",
            16,
            limit_exclusion,
            5,
            SEVERITY.MEDIUM.value,
            "Configuration",
            "Authentication exclusions is not restricted.",
        )

    def audit_security(server: Server) -> Rule:

        """
        This function checks the security configuration.
        """

        return Rule(
            "Security configuration",
            3,
            server.security,
            6,
            SEVERITY.HIGH.value,
            "Configuration",
            "Security configuration is not True.",
        )

    def audit_debug(server: Server) -> Rule:

        """
        This function checks the debug configuration.
        """

        return Rule(
            "Debug mode",
            4,
            not server.debug,
            6,
            SEVERITY.HIGH.value,
            "Configuration",
            "Debug configuration is not False.",
        )

    def audit_blacklist(server: Server) -> Rule:

        """
        This function checks the blacklist configuration.
        """

        return Rule(
            "Blacklist configuration",
            5,
            server.configuration.auth_failures_to_blacklist is not None
            and server.configuration.blacklist_time is not None,
            7,
            SEVERITY.HIGH.value,
            "Configuration",
            "Blacklist is not configured.",
        )

    def audit_smtp_password(server: Server) -> Rule:

        """
        This function checks the SMTP password protection.
        """

        return Rule(
            "SMTP password protection",
            6,
            getattr(server.configuration, "smtp_password", None) is None
            or (
                server.configuration.smtp_starttls
                or server.configuration.smtp_ssl
            ),
            7,
            SEVERITY.HIGH.value,
            "Configuration",
            "SMTP password is not protected.",
        )

    def audit_log_level(server: Server) -> Rule:

        """
        This function checks the log level.
        """

        return Rule(
            "Log level",
            7,
            not server.configuration.log_level,
            5,
            SEVERITY.MEDIUM.value,
            "Configuration",
            "Log level is not 0.",
        )

    def audits_module_path(server: Server) -> Rule:

        """
        This function checks the modules paths.
        """

        for module_path in server.configuration.modules_path:
            yield Rule(
                "Module path",
                30,
                isabs(module_path),
                5,
                SEVERITY.MEDIUM.value,
                "Configuration",
                f"Module path {module_path} is not absolute.",
            )

    def audits_scripts_logs(server: Server) -> Iterator[Rule]:

        """
        This function checks the configuration of the script log.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Command log",
                8,
                script.no_password,
                1,
                SEVERITY.INFORMATION.value,
                "Script Configuration",
                f"Script command is not logged for {script.name}.",
            )

    def audits_scripts_stderr_content_type(server: Server) -> Iterator[Rule]:

        """
        This function checks the configuration of the script stderr content
        type.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Error content type",
                9,
                script.stderr_content_type == "text/plain",
                6,
                SEVERITY.HIGH.value,
                "Script Configuration",
                "The content type of the stderr for "
                f"{script.name} is not text/plain.",
            )

    def audits_scripts_content_type(server: Server) -> Iterator[Rule]:

        """
        This function checks the configuration of the script content type.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Output content type",
                10,
                script.content_type == "text/plain",
                1,
                SEVERITY.INFORMATION.value,
                "Script Configuration",
                "The content type of the script named "
                f"{script.name} is not text/plain.",
            )

    def audits_scripts_path(server: Server) -> Iterator[Rule]:

        """
        This function checks the configuration of the script path.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Script path",
                17,
                script.path_is_defined and isabs(script.path),
                7,
                SEVERITY.HIGH.value,
                "Script Configuration",
                f"The path of {script.name} is not defined in configuration"
                " files or is not absolute.",
            )

            delattr(script, "path_is_defined")

    def audits_launcher(server: Server) -> Iterator[Rule]:

        """
        This function checks the configuration of the script launcher.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Script launcher",
                18,
                script.launcher and isabs(script.launcher),
                7,
                SEVERITY.HIGH.value,
                "Script Configuration",
                f"The path of {script.name} launcher is not defined in"
                " configuration files or is not absolute.",
            )

    def audit_admin_account(server: Server) -> Iterator[Rule]:

        """
        This function checks the admin password.
        """

        default_password = False

        with open(join(server_path, "data", "users.csv")) as file:
            line = file.readline()

            while line:
                if (
                    "pZo8c8+cKLTHFaUBxGwcYaFDgNRw9HHph4brixOo6OMusF"
                    "KbfkBEObZiNwda/f9W3+IpiMY8kqiFmQcbkUCbGw==" in line
                ):
                    default_password = True
                    break
                line = file.readline()

        return Rule(
            "Default credentials",
            11,
            not default_password,
            7,
            SEVERITY.HIGH.value,
            "Password",
            "Admin password is Admin.",
        )

    def get_owner(filename: str) -> str:

        """
        This function return the owner of a file.
        """

        if Audit.is_windows:
            with suppress(ImportError):
                import win32security

                sid = win32security.GetFileSecurity(
                    filename, win32security.OWNER_SECURITY_INFORMATION
                ).GetSecurityDescriptorOwner()
                name, _, _ = win32security.LookupAccountSid(None, sid)

                return name
        else:
            from os import stat
            from pwd import getpwuid

            return getpwuid(stat(filename).st_uid).pw_name

    def audits_file_owner(server: Server) -> Iterator[Rule]:

        """
        This function checks the files owner.
        """

        user = getuser()
        current_dir = Audit.current_dir

        simple_filenames = []

        if Audit.is_windows:
            important_filenames = [
                join(server_path, "config", "nt", "server.ini"),
                join(server_path, "config", "nt", "server.json"),
            ]
        else:
            important_filenames = [
                join(server_path, "config", "server.ini"),
                join(server_path, "config", "server.json"),
            ]

        important_filenames.append(join(server_path, "config", "loggers.ini"))
        important_filenames.append(join(current_dir, "config", "server.ini"))
        important_filenames.append(join(current_dir, "config", "server.json"))

        important_filenames += listdir("logs")
        important_filenames += listdir(join(server_path, "data"))

        # for dirname_ in (server_path, current_dir):

        for file in server.pages.js_paths.values():
            if exists(file.path):
                simple_filenames.append(file.path)

        for file in server.pages.statics_paths.values():
            if exists(file.path):
                simple_filenames.append(file.path)

        for script in server.pages.scripts.values():
            important_filenames.append(script.path)

        for module in server.pages.packages.__dict__.values():
            if isinstance(module, ModuleType):
                important_filenames.append(module.__file__)

        for filename in important_filenames:
            if exists(filename):
                yield Rule(
                    "File owner",
                    11,
                    user == Audit.get_owner(filename),
                    10,
                    SEVERITY.CRITICAL.value,
                    "Files",
                    f"File owner is not {user} for {filename}.",
                )

        for filename in simple_filenames:
            if exists(filename):
                yield Rule(
                    "File owner",
                    11,
                    user == Audit.get_owner(filename),
                    4,
                    SEVERITY.MEDIUM.value,
                    "Files",
                    f"File owner is not {user} for {filename}.",
                )

    def get_permissions(filename: str) -> str:

        """
        This function returns the file permissions.
        """

        return filemode(stat(filename).st_mode)

    def _audits_directory_permissions(
        server: Server, secure_paths: Set[str]
    ) -> Iterator[Rule]:

        """
        This function checks owner and permissions on bin directory.
        """

        if Audit.is_windows:
            yield Rule(
                "Directory permissions",
                33,
                False,
                1,
                SEVERITY.INFORMATION.value,
                "Files",
                "Directory permissions is not check on Windows.",
            )
            return

        config_path = join(server_path, "config")
        secure_paths = {
            join(prefix, "bin"),
            config_path,
            join(config_path, "files"),
            join(config_path, "scripts"),
            Audit.current_dir,
        }
        secure_paths.update(secure_paths)

        for path_ in secure_paths:
            yield Rule(
                "Directory owner",
                33,
                Audit.get_owner(path_) == "root",
                10,
                SEVERITY.CRITICAL.value,
                "Files",
                f"Directory owner for {path_} is not root.",
            )

            yield Rule(
                "Directory permissions",
                34,
                Audit.get_permissions(path_) == "drwxr-xr-x",
                10,
                SEVERITY.CRITICAL.value,
                "Files",
                f"Directory permissions for {path_} is not 755 (drwxr-xr-x).",
            )

    def audits_timeout(server: Server) -> Iterator[Rule]:

        """
        This function checks scripts timeout.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Script timeout",
                35,
                script.timeout,
                5,
                SEVERITY.MEDIUM.value,
                "Script Configuration",
                f"The {script.name} timeout is not defined.",
            )

    def audits_file_rights(server: Server) -> Iterator[Rule]:

        """
        This function checks the files rights.
        """

        if Audit.is_windows:
            yield Rule(
                "File permissions",
                12,
                False,
                1,
                SEVERITY.INFORMATION.value,
                "Files",
                "Files rights is not check on Windows.",
            )
            return

        current_dir = Audit.current_dir

        rw_filenames = listdir(join(server_path, "data")) + listdir(
            join(current_dir, "logs")
        )

        server_logs = join(server_path, "logs")
        if exists(server_logs):
            rw_filenames.extend(listdir(server_logs))

        r_filenames = [
            join(server_path, "config", "server.ini"),
            join(server_path, "config", "server.json"),
        ]

        r_filenames.append(join(server_path, "config", "loggers.ini"))
        r_filenames.append(join(current_dir, "config", "server.ini"))
        r_filenames.append(join(current_dir, "config", "server.json"))

        # for dirname_ in (server_path, current_dir):

        r_filenames += [
            file.path
            for file in server.pages.js_paths.values()
            if exists(file.path)
        ]

        r_filenames += [
            file.path
            for file in server.pages.statics_paths.values()
            if exists(file.path)
        ]

        executable_filenames = [
            script.path for script in server.pages.scripts.values()
        ]

        executable_filenames += [
            module.__file__
            for module in server.pages.packages.__dict__.values()
            if isinstance(module, ModuleType)
        ]

        yield from Audit._audits_directory_permissions(
            server,
            {
                dirname(path_)
                for path_ in executable_filenames + rw_filenames + r_filenames
                if exists(path_)
            },
        )

        yield from [
            Rule(
                "File permissions (rw-)",
                12,
                Audit.get_permissions(filename)
                in ("-rw-------", "-r--------"),
                10,
                SEVERITY.CRITICAL.value,
                "Files",
                f"File rights for {split(filename)[1]} is "
                "not 600 (rw- --- ---).",
            )
            for filename in rw_filenames
            if exists(filename)
        ]

        yield from [
            Rule(
                "File permissions (r--)",
                12,
                Audit.get_permissions(filename) == "-r--------",
                10,
                SEVERITY.CRITICAL.value,
                "Files",
                f"File rights for {split(filename)[1]} is "
                "not 400 (r-- --- ---).",
            )
            for filename in r_filenames
            if exists(filename)
        ]

        for filename in executable_filenames:
            if exists(filename):
                permissions = Audit.get_permissions(filename)

                yield Rule(
                    "File permissions (r-x)",
                    12,
                    permissions.endswith("------") and "w" not in permissions,
                    10,
                    SEVERITY.CRITICAL.value,
                    "Files",
                    f"File rights for {split(filename)[1]} is not 0 "
                    "for group and 0 for other (xxx --- ---).",
                )

    def audit_export_configuration(server: Server) -> Iterator[Rule]:

        """
        This function checks the export configuration file.
        """

        return Rule(
            "Export file",
            13,
            not exists("export_Configuration.json"),
            4,
            SEVERITY.MEDIUM.value,
            "Files",
            "The export configuration file exist, "
            "should be deleted on production.",
        )

    def log_rule(rule: Rule, logs: Logs) -> None:

        """
        This function log rule.
        """

        if rule.is_OK:
            state = "PASS"
        else:
            state = "FAIL"

        log = (
            f"Audit -> state: {state}, ID: {rule.id_}, severity: "
            f"{rule.severity}, level: {rule.level}, category: {rule.category}"
            f', subject: "{rule.subject}", reason: "{rule.reason}".'
        )

        if rule.is_OK or SEVERITY.INFORMATION.value == rule.severity:
            logs.debug(log)
        elif SEVERITY.LOW.value == rule.severity:
            logs.info(log)
        elif SEVERITY.MEDIUM.value == rule.severity:
            logs.warning(log)
        elif SEVERITY.HIGH.value == rule.severity:
            logs.error(log)
        elif SEVERITY.CRITICAL.value == rule.severity:
            logs.critical(log)

    def run(server: Server, logs: Logs) -> List[Rule]:

        """
        This function run audit and checks.
        """

        rules = []
        for audit in dir(Audit):
            if audit.startswith("audit_"):
                rule = getattr(Audit, audit)(server)
                Audit.log_rule(rule, logs)
                rules.append(rule)
            elif audit.startswith("audits_"):
                for rule in getattr(Audit, audit)(server):
                    Audit.log_rule(rule, logs)
                    rules.append(rule)

        return rules

    def check_for_updates(logs: Logs) -> None:

        """
        This function runs in a thread indefinitely, it checks the version
        and the latest published version of WebScripts every hour.
        If the version and the latest published version are different,
        this function sends an email notification.
        """

        latest = Audit.latest
        latest_ = Audit.latest_

        if __package__:
            version = [
                int(i) for i in modules[__package__].__version__.split(".")
            ]
        else:
            return None

        def get_latest() -> str:

            """
            This function request github api and return the latest version.
            """

            logs.debug(
                "Request github API to get latest version of WebScripts..."
            )
            response = urlopen(  # nosec
                "https://api.github.com/repos/mauricelambert/WebScripts/tags"
            )

            data = load(response)
            return [int(i) for i in data[0]["name"][1:].split(".")]

        if Audit.network_up:
            try:
                latest = Audit.latest = get_latest()
            except URLError:
                logs.critical("Network error: updates are not checked.")
                Audit.network_up = False

            if version < latest and latest != latest_:
                logs.critical(
                    "WebScripts is not up-to-date, current:"
                    f" {version} latest: {latest}"
                )
                return (
                    f"Current WebScripts version: {'.'.join(version)}\n"
                    f"Latest WebScripts version: {'.'.join(latest)}.\nIt is "
                    "recommended that you upgrade your WebScripts server."
                )

            Audit.latest_ = latest

        return ""


class FilesIntegity:

    """
    This class checks the file integrity.
    """

    def __init__(self, server, logs):
        directory = Audit.current_dir
        webscripts_filenames = (
            join(directory, "webscripts_file_integrity.json"),
            join(server_path, "webscripts_file_integrity.json"),
        )
        for path in webscripts_filenames:
            if exists(path):
                self.webscripts_filename = path
                break

        uploads_filenames = (
            join(directory, "uploads_file_integrity.json"),
            join(server_path, "uploads_file_integrity.json"),
        )
        for path in uploads_filenames:
            if exists(path):
                self.uploads_filename = path
                break

        logs_filenames = (
            join(directory, "logs_checks.json"),
            join(server_path, "logs_checks.json"),
        )
        for path in logs_filenames:
            if exists(path):
                self.logs_filename = path
                break

        self.temp_logs_files = {}
        self.server = server
        self.logs = logs
        self.hashes = {}

    def get_old_files(
        self, filename: str, hash_: str
    ) -> Dict[str, Dict[str, str]]:

        """
        This function returns file data to check integrity
        from JSON file (previous check).
        """

        logs = self.logs
        logs.debug("Get old file data for integrity checks.")
        to_yield = None

        with open(filename, "rb") as file:
            data = file.read()
            files = loads(data)
            if hash_ is not None:
                if newhash("sha512", data).hexdigest() != hash_:
                    logs.critical("File for integrity checks is compromised.")
                    to_yield = {
                        "File": filename,
                        "Reason": "File for integrity checks is compromised.",
                        "Score": 10,
                    }

        return to_yield, files

    def get_files(self) -> Dict[str, Dict[str, str]]:

        """
        This functions gets used files.
        """

        def build_file(path: str) -> Dict[str, str]:

            """
            This function makes file JSON object from path.
            """

            file = open(path, "rb")
            data = file.read()
            file.close()

            self.logs.debug(f"Get hashes and metadata for {path}.")
            metadata = stat(path)

            return {
                "path": path,
                "sha512": newhash("sha512", data).hexdigest(),
                "whirlpool": newhash("whirlpool", data).hexdigest(),
                "size": metadata.st_size,
                "modification": strftime(
                    "%Y-%m-%d %H:%M:%S", localtime(metadata.st_mtime)
                ),
            }

        server = self.server
        pages = server.pages
        self.webscripts_new_files = files = {}
        self.logs.info("Get hash and metadata from code files...")

        templates = []

        for name, callable_file in pages.js_paths.items():
            if not templates:
                templates = [
                    callable_file.template_index_path,
                    callable_file.template_script_path,
                    callable_file.template_header_path,
                    callable_file.template_footer_path,
                ]
            files[f"js {name}"] = build_file(callable_file.path)

        for name, callable_file in pages.statics_paths.items():
            if not templates:
                templates = [
                    callable_file.template_index_path,
                    callable_file.template_script_path,
                ]
            files[f"static {name}"] = build_file(callable_file.path)

        for name, config in pages.scripts.items():
            files[f"script {name}"] = build_file(config.path)

        for path in glob(join(server_path, "*.py")):
            files[f"webscript {basename(path)}"] = build_file(path)

        for path in [
            join("config", "server.ini"),
            join("config", "server.json"),
            join("config", "nt", "server.ini"),
            join("config", "nt", "server.json"),
            join(server_path, "config", "server.ini"),
            join(server_path, "config", "server.json"),
            join(server_path, "config", "nt", "server.ini"),
            join(server_path, "config", "nt", "server.json"),
        ]:
            if exists(path):
                files[f"server configuration {basename(path)}"] = build_file(
                    path
                )

        for path in server.configuration.configuration_files:
            files[f"script configuration {basename(path)}"] = build_file(path)

        for template in templates:
            files[f"template {basename(template)}"] = build_file(template)

        module_path = join(server_path, "modules")
        for filename, path in get_files_recursive(module_path):
            files[f"server modules {filename}"] = build_file(
                join(module_path, path)
            )

        module_path = join(Audit.current_dir, "modules")
        for filename, path in get_files_recursive(module_path):
            files[f"current modules {filename}"] = build_file(
                join(module_path, path)
            )

        for script in scandir(dirname(executable)):
            if script.is_file():
                files[f"venv scripts/bin {script.name}"] = build_file(
                    script.path
                )

        return files

    def check_webscripts_file_integrity(self) -> Iterator[Dict[str, str]]:

        """
        This function compares old files data to new files data.
        """

        new_files_bak = self.get_files()
        new_files = new_files_bak.copy()
        self.logs.debug("Compare metadata and hashes for code files.")
        to_yield, old_files = self.get_old_files(
            self.webscripts_filename, self.hashes.get("webscripts")
        )

        if to_yield:
            yield to_yield

        for file, data in old_files.items():
            new_data = new_files.pop(file, {})

            for check, old_default, new_default, score in (
                ("path", "??", "::", 10),  # default values are invalid.
                # A hacker can make new file with different path when
                # you have a weak configuration (WebScripts server
                # research files).
                ("sha512", "ZZ", "XX", 7),  # if file change this check
                ("whirlpool", "ZZ", "XX", 10),  # should failed so any other
                ("size", -1, -2, 10),  # should be failed.
                ("modification", "~~", "!!", 10),
            ):

                old = data.get(check, old_default)
                new = new_data.get(check, new_default)

                if old != new:
                    self.logs.critical(f"Code file: {file} is compromised.")
                    yield {
                        "File": file,
                        "Reason": (
                            f"New {check} for '{file}' "
                            f"(Old: {old if old != old_default else None},"
                            f" New: {new if new != new_default else None})"
                        ),
                        "Score": score,
                    }

        for file, data in new_files.items():
            self.logs.critical(f"Code file: {file} is compromised.")
            yield {
                "File": file,
                "Reason": (
                    f"A new file is detected: '{file}' "
                    f"(Last modification: {data.get('modification')})"
                ),
                "Score": 5,
            }

    def check_data_file_integrity(self) -> Iterator[Dict[str, str]]:

        """
        This function checks uploads file integrity
        (uploads can not be changed from WebScripts Server).
        """

        data_files = join(server_path, "data")
        uploads_files = join(data_files, "uploads")
        self.new_data_files = new_data_files = {}
        to_yield, old_files = self.get_old_files(
            self.uploads_filename, self.hashes.get("uploads")
        )

        if to_yield:
            yield to_yield

        for file in scandir(data_files):
            if not file.is_file():
                continue

            name = f"Data {file.name}"
            path = file.path
            data = old_files.pop(name, None)
            hash_ = sha512sum(path)
            metadata = stat(path)
            size = metadata.st_size
            modif = strftime("%Y-%m-%d %H:%M:%S", localtime(metadata.st_mtime))

            new_data_files[name] = {
                "size": size,
                "hash": hash_,
                "modification": modif,
            }

            if data is None:
                self.logs.info(
                    f"A new database file has been created ({name})."
                )
                yield {
                    "File": name,
                    "Reason": "A new database file has been created.",
                    "Score": 1,
                }
                continue

            if (
                data.get("size", -1) != size
                or data.get("modification", "") != modif
                or hash_ != data.get("hash", "")
            ):
                self.logs.warning(
                    f"Database file: '{file}' has been modified."
                )
                yield {
                    "File": name,
                    "Reason": "A database has been modified.",
                    "Score": 2,
                }

        for filename in listdir(uploads_files):
            path = join(uploads_files, filename)
            filename = f"Uploads {filename}"
            data = old_files.pop(filename, None)
            hash_ = sha512sum(path)
            metadata = stat(path)
            size = metadata.st_size
            modif = strftime("%Y-%m-%d %H:%M:%S", localtime(metadata.st_mtime))

            new_data_files[filename] = {
                "size": size,
                "hash": hash_,
                "modification": modif,
            }

            if data is None:
                self.logs.info(
                    f"An uploads file has been created ({filename})."
                )
                yield {
                    "File": filename,
                    "Reason": "An uploads file has been created.",
                    "Score": 1,
                }
                continue

            if (
                data.get("size", -1) != size
                or data.get("modification", -1) != modif
                or hash_ != data.get("hash", "")
            ):
                self.logs.critical(
                    "An uploads file has been modified (this is a suspicious "
                    "action, check that your server is not compromised)"
                    f" [{filename}]."
                )
                yield {
                    "File": filename,
                    "Reason": (
                        "An uploads file has been modified (this is a "
                        "suspicious action, check that your server is not "
                        "compromised)."
                    ),
                    "Score": 10,
                }

        for file in old_files:
            self.logs.critical(
                "An data/uploads file is deleted (this is a suspicious action,"
                f" check that your server is not compromised) [{file}]."
            )
            yield {
                "File": file,
                "Reason": (
                    "A data/uploads is deleted (this is a suspicious action,"
                    " check that your server is not compromised)."
                ),
                "Score": 10,
            }

    def check_logs_files(self) -> Iterator[Dict[str, str]]:

        """
        This function checks logs file.
        """

        self.logs.debug("Log files integrity checks...")
        temp_logs_files = self.temp_logs_files
        check_logs_ok = self.check_logs_ok
        _, self.logs_checks = to_yield, logs_checks = self.get_old_files(
            self.logs_filename, self.hashes.get("logs")
        )

        if to_yield:
            yield to_yield

        server_log_path = join(server_path, "logs")
        if isdir(server_log_path):
            files = [*scandir(server_log_path)]
        else:
            files = []

        if isdir("logs"):
            self.logs.info("Current logs directory found...")
            files.extend(scandir("logs"))

        for file in files:
            filename = file.name
            if (
                file.is_file()
                and len(filename) > 3
                and filename[:2].isdigit()
                and filename[2] == "-"
                and filename.endswith(".logs")
            ):
                self.logs.debug(f"Check log file: '{filename}'...")
                path = file.path
                metadata = file.stat()
                size = metadata.st_size
                modification = strftime(
                    "%Y-%m-%d %H:%M:%S", localtime(metadata.st_mtime)
                )
                creation = strftime(
                    "%Y-%m-%d %H:%M:%S", localtime(metadata.st_ctime)
                )
                temp_file = temp_logs_files.get(path)

                if temp_file is None:
                    temp_file = temp_logs_files[path] = TemporaryFile()

                if not check_logs_ok(path, temp_file, metadata):
                    file_checks = logs_checks.get(file, {})
                    self.logs.warning(
                        "A log file has lost logs (check log rotation "
                        "otherwise your server is compromised)."
                    )
                    yield {
                        "File": f"Logs {file}",
                        "Reason": (
                            f"{path}: logs has been modified. "
                            f"Last size: {file_checks.get('size')},"
                            f" new size: {size}. Last creation: "
                            f"{file_checks.get('created')}, last modification:"
                            f" {file_checks.get('modification')}, new creation"
                            f": {creation}, new modification: {modification}. "
                            "If it's not rotating logs, your server is"
                            " compromised."
                        ),
                        "Score": 7,
                        # score 7 because it will be reported on
                        # logs file rotation
                    }

                logs_checks[path] = {
                    "modification": modification,
                    "created": creation,
                    "size": size,
                }

                self.logs.debug(f"Log file: '{filename}' is checked.")

    def save(self) -> None:

        """
        This function saves data to check file integrity.
        """

        data_webscripts = dumps(self.webscripts_new_files).encode()
        with open(self.webscripts_filename, "wb") as file:
            file.write(data_webscripts)

        data_uploads = dumps(self.new_data_files).encode()
        with open(self.uploads_filename, "wb") as file:
            file.write(data_uploads)

        data_logs = dumps(self.logs_checks).encode()
        with open(self.logs_filename, "wb") as file:
            file.write(data_logs)

        self.hashes = {
            "webscripts": newhash("sha512", data_webscripts).hexdigest(),
            "uploads": newhash("sha512", data_uploads).hexdigest(),
            "logs": newhash("sha512", data_logs).hexdigest(),
        }

    @staticmethod
    def check_logs_ok(
        path: str, temp_file: TemporaryFile, metadata: stat_result
    ) -> bool:

        """
        This function checks the log file integrity.
        """

        temp_metadata = stat(temp_file.name)
        temp_file.seek(0)
        read_check_log = temp_file.readline
        write_check_log = temp_file.write

        if (
            temp_metadata.st_size > metadata.st_size
            # or temp_metadata.st_mtime > metadata.st_mtime
            or temp_metadata.st_ctime < metadata.st_ctime
        ):
            return False

        with open(path, "rb") as log_file:
            read_log = log_file.readline
            log = read_log()
            check_log = read_check_log()

            while check_log:
                if log != check_log:
                    temp_file.seek(0)
                    log_file.seek(0)
                    copyfileobj(log_file, temp_file)
                    return False

                log = read_log()
                check_log = read_check_log()

            while log:
                write_check_log(log)
                log = read_log()

        return True


def sha512sum(path: str, length: int = DEFAULT_BUFFER_SIZE) -> str:

    """
    This function returns the SHA512 of a file.
    """

    hash_ = newhash("sha512")
    update = hash_.update
    with open(path, mode="rb") as file:
        read = file.read
        data = read(length)

        while data:
            update(data)
            data = read(length)

    return hash_.hexdigest()


def daemon_func(
    server: Server,
    file_integrity: FilesIntegity,
    logs: Logs,
    send_mail: Callable,
) -> None:

    """
    This function implements a daemon thread to
    check WebScripts version, update and integrity.
    """

    sleep(120)  # No SMTP error: "SmtpError: to many connections"
    files = []
    text = ""

    while True:
        text += Audit.check_for_updates(logs)

        if text:
            send_mail(server.configuration, text)

        sleep(3600)
        files += [
            *file_integrity.check_webscripts_file_integrity(),
            *file_integrity.check_logs_files(),
            *file_integrity.check_data_file_integrity(),
        ]

        file_integrity.save()

        # if [file for file in files if file["Score"] == 10]:
        if any([file["Score"] >= 5 for file in files]):
            lengths = {
                "File": {"length": 12},
                "Reason": {"length": 50},
                "Score": {"length": 5, "separator": ",\n"},
            }
            text = "\n".join(
                [
                    Report.truncate_string(key, **lengths[key])
                    for key in files[0].keys()
                ]
                + [
                    Report.truncate_string(value, **lengths[key])
                    for file in files
                    for key, value in file.items()
                ]
            )
            files = []
        else:
            text = ""


def get_files_recursive(path: str) -> Iterator[Tuple[str, str]]:

    """
    This function returns path and file names recursively.
    """

    if not isdir(path):
        return None

    for file in listdir(path):
        if isfile(file):
            yield join(path, file), file
        elif isdir(file):
            yield from get_files_recursive(join(path, file))


def main(server: Server, logs: Logs, send_mail: Callable) -> Report:

    """
    The main function to perform WebScripts Server hardening audit.
    """

    file_integrity = FilesIntegity(server, logs)

    files = [
        *file_integrity.check_webscripts_file_integrity(),
        *file_integrity.check_logs_files(),
        *file_integrity.check_data_file_integrity(),
    ]

    file_integrity.save()

    rules = Audit.run(server, logs)
    report = Report(rules, files, server, logs)
    report.as_json()
    report.get_pourcent()
    report.as_html()
    report.as_text()

    with open("audit.json", "w") as file:
        file.write(report.reports_json)

    with open("audit.html", "w") as file:
        file.write(report.reports_html)

    with open("audit.txt", "w") as file:
        file.write(report.reports_text)

    logs.debug("Start a thread to send hardening report...")
    Thread(target=report.notification).start()

    logs.debug("Start the daemon to check WebScripts version and integrity...")
    daemon = Thread(
        target=daemon_func,
        args=(
            server,
            file_integrity,
            logs,
            send_mail,
        ),
        daemon=True,
    )
    daemon.start()

    return report
