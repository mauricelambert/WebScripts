#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tools run scripts and display the result in a Web Interface.
#    Copyright (C) 2021  Maurice Lambert

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

"""This tools run scripts and display the result in a Web Interface.

This file implement the hardening audit of the WebScripts installation and
configuration."""

__version__ = "0.3.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This tools run scripts and display the result in a Web
Interface.

This file implement the hardening audit of the WebScripts installation and
configuration."""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Report", "Rule", "Audit", "SEVERITY", "main"]

from email.message import EmailMessage
from collections.abc import Callable
from os import getcwd, path, listdir
from collections.abc import Iterator
from smtplib import SMTP, SMTP_SSL
from urllib.request import urlopen
from urllib.error import URLError
from dataclasses import dataclass
from socket import gethostbyname
from pkgutil import iter_modules
from typing import TypeVar, List
from contextlib import suppress
from operator import itemgetter
from types import ModuleType
from threading import Thread
from getpass import getuser
from time import sleep
from enum import Enum
import platform
import ctypes
import json
import stat
import sys
import re
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
server_path = path.dirname(__file__)


class SEVERITY(Enum):

    """Severity level of the rules."""

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

    """This class implement a rule for hardening."""

    subject: str
    id_: int
    is_OK: bool
    level: int
    severity: str
    category: str
    reason: str


class Report:

    """This class implement the report object."""

    def __init__(self, rules: List[Rule], server: Server, logs: Logs):
        self.rules = rules
        self.server = server
        self.logs = logs
        self.reports_json: str = None
        self.reports_dict: str = None
        self.reports_text: str = None
        self.reports_html: str = None

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
            string = f"{string[:length - len(end)]}...{separator}"
        else:
            string = f"{string}{separator}{' ' * (length - length_string)}"

        return string

    def as_json(self) -> str:

        """This function returns a JSON string of audit results."""

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
        self.reports_json = json.dumps(self.reports_dict, indent=4)
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

        if self.reports_dict is None:
            self.as_json()

        table = (
            f"<tr><td>{'</td><td>'.join(G.field(self.reports_dict))}"
            "</td></tr>"
        )

        table_fail = self.get_HTML_table(table, G.fail(self.reports_dict))
        table_critical = self.get_HTML_table(table, G.crit(self.reports_dict))
        table_high = self.get_HTML_table(table, G.high(self.reports_dict))
        table_medium = self.get_HTML_table(table, G.med(self.reports_dict))
        table_low = self.get_HTML_table(table, G.low(self.reports_dict))
        table_information = self.get_HTML_table(
            table, G.info(self.reports_dict)
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
        </style>
    </head>
    <body>
        <h1>WebScripts: Hardening Audit Report</h1>

        <h2>Links</h2>
        <ul>
            <li><a href="#scoring">Scoring</a></li>
            <li><a href="#failed">Failed</a></li>
            <li><a href="#critical">Critical</a></li>
            <li><a href="#high">High</a></li>
            <li><a href="#medium">Medium</a></li>
            <li><a href="#low">Low</a></li>
            <li><a href="#information">Information</a></li>
        </ul>

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
    - ALL:         Total:\t{G.total(scoring)},\
\t Fail:\t{G.fail(scoring)},\t Pourcent:\t\
{self.pourcent['ALL']}%
    - CRITICAL:    Total:\t\
{scoring[f"{SEVERITY.CRITICAL.value} total"]},\t Fail:\t\
{scoring[f"{SEVERITY.CRITICAL.value} fail"]},\t \
Pourcent:\t{G.crit(self.pourcent)}%
    - HIGH:        Total:\t\
{scoring[f"{SEVERITY.HIGH.value} total"]},\t Fail:\t\
{scoring[f"{SEVERITY.HIGH.value} fail"]},\t Pourcent:\t\
{G.high(self.pourcent)}%
    - MEDIUM:      Total:\t\
{scoring[f"{SEVERITY.MEDIUM.value} total"]},\t Fail:\t\
{scoring[f"{SEVERITY.MEDIUM.value} fail"]},\t Pourcent:\
\t{G.med(self.pourcent)}%
    - LOW:         Total:\t\
{scoring[f"{SEVERITY.LOW.value} total"]},\t Fail:\t\
{scoring[f"{SEVERITY.LOW.value} fail"]},\t Pourcent:\t\
{G.low(self.pourcent)}%
    - INFORMATION: Total:\t{
scoring[f"{SEVERITY.INFORMATION.value} total"]},\t Fail:\
\t{scoring[f"{SEVERITY.INFORMATION.value} fail"]},\t\
 Pourcent:\t{G.info(self.pourcent)}%

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

        """This function send an email notification
        to administrator with the audit report."""

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

    """This function implement hardening checks."""

    is_windows = platform.system() == "Windows"

    def audit_in_venv(server: Server) -> Rule:

        """This function check the virtualenv."""

        return Rule(
            "Virtualenv",
            0,
            sys.prefix != sys.base_prefix,
            3,
            SEVERITY.LOW.value,
            "Installation",
            "WebScripts is not install in virtualenv.",
        )

    def audit_config_files(server: Server) -> Rule:

        """This function check the configurations files."""

        files = [
            path.join("config", "server.ini"),
            path.join("config", "server.json"),
            path.join(server_path, "config", "nt", "server.ini")
            if Audit.is_windows
            else path.join(server_path, "config", "server.ini"),
            path.join(server_path, "config", "nt", "server.json")
            if Audit.is_windows
            else path.join(server_path, "config", "server.json"),
        ]
        compteur = 0

        for file in files:
            if path.isfile(file):
                compteur += 1

        return Rule(
            "Configurations files",
            31,
            compteur <= 1,
            7,
            SEVERITY.HIGH.value,
            "Installation",
            "WebScripts should be configured by only one configuration file.",
        )

    def audit_venv_modules(server: Server) -> Rule:

        """This function check the virtualenv modules."""

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
                "_distutils_hack",
                "uploads_management",
            ]

        for module in iter_modules():
            if (
                module.module_finder.path.startswith(sys.prefix)
                and module.name not in preinstall_modules
            ):
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

        """This function check the user."""

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

        """This function check the network interface."""

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

        """This function check authentication is forced."""

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

        """This function check authentication is enabled."""

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

        """This function check exclusions for authentication."""

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

        """This function check the security configuration."""

        return Rule(
            "Security configuration",
            3,
            server.security,
            8,
            SEVERITY.CRITICAL.value,
            "Configuration",
            "Security configuration is not True.",
        )

    def audit_debug(server: Server) -> Rule:

        """This function check the debug configuration."""

        return Rule(
            "Debug configuration",
            4,
            not server.debug,
            8,
            SEVERITY.CRITICAL.value,
            "Configuration",
            "Debug configuration is not False.",
        )

    def audit_blacklist(server: Server) -> Rule:

        """This function check the blacklist configuration."""

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

        """This function check the SMTP password protection."""

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

        """This function check the log level."""

        return Rule(
            "Log level",
            7,
            not server.configuration.log_level,
            8,
            SEVERITY.HIGH.value,
            "Configuration",
            "Log level is not 0.",
        )

    def audits_module_path(server: Server) -> Rule:

        """This function check the modules paths."""

        for module_path in server.configuration.modules_path:
            yield Rule(
                "Module path",
                30,
                path.isabs(module_path),
                5,
                SEVERITY.MEDIUM.value,
                "Configuration",
                f"Module path {module_path} is not absolute.",
            )

    def audits_scripts_logs(server: Server) -> Iterator[Rule]:

        """This function check the configuration of the script log."""

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
        This function check the configuration of the script stderr content
        type.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Error content type",
                9,
                script.stderr_content_type == "text/plain",
                8,
                SEVERITY.CRITICAL.value,
                "Script Configuration",
                "The content type of the stderr for "
                f"{script.name} is not text/plain.",
            )

    def audits_scripts_content_type(server: Server) -> Iterator[Rule]:

        """
        This function check the configuration of the script content type.
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

        """This function check the configuration of the script path."""

        for script in server.pages.scripts.values():
            yield Rule(
                "Script path",
                17,
                script.path_is_defined and path.isabs(script.path),
                5,
                SEVERITY.MEDIUM.value,
                "Script Configuration",
                f"The path of {script.name} is not defined in configuration"
                " files or is not absolute.",
            )

            delattr(script, "path_is_defined")

    def audits_launcher(server: Server) -> Iterator[Rule]:

        """This function check the configuration of the script launcher."""

        for script in server.pages.scripts.values():
            yield Rule(
                "Script launcher",
                18,
                script.launcher and path.isabs(script.launcher),
                7,
                SEVERITY.HIGH.value,
                "Script Configuration",
                f"The path of {script.name} launcher is not defined in"
                " configuration files or is not absolute.",
            )

    def audit_admin_account(server: Server) -> Iterator[Rule]:

        """This function check the admin password."""

        default_password = False

        with open(path.join(server_path, "data", "users.csv")) as file:
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
            "Admin password",
            11,
            not default_password,
            10,
            SEVERITY.CRITICAL.value,
            "Password",
            "Admin password is Admin.",
        )

    def get_owner(filename: str) -> str:

        """This function return the owner of a file."""

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

        """This function check the files owner."""

        user = getuser()
        current_dir = getcwd()

        simple_filenames = []

        if Audit.is_windows:
            important_filenames = [
                path.join(server_path, "config", "nt", "server.ini"),
                path.join(server_path, "config", "nt", "server.json"),
            ]
        else:
            important_filenames = [
                path.join(server_path, "config", "server.ini"),
                path.join(server_path, "config", "server.json"),
            ]

        important_filenames.append(
            path.join(server_path, "config", "loggers.ini")
        )
        important_filenames.append(
            path.join(current_dir, "config", "server.ini")
        )
        important_filenames.append(
            path.join(current_dir, "config", "server.json")
        )

        important_filenames += listdir("logs")
        important_filenames += listdir(path.join(server_path, "data"))

        for dirname in (server_path, current_dir):

            for file in server.pages.js_paths.values():
                if path.exists(file.path):
                    simple_filenames.append(file.path)

            for file in server.pages.statics_paths.values():
                if path.exists(file.path):
                    simple_filenames.append(file.path)

        for script in server.pages.scripts.values():
            important_filenames.append(script.path)

        for module in server.pages.packages.__dict__.values():
            if isinstance(module, ModuleType):
                important_filenames.append(module.__file__)

        for filename in important_filenames:
            if path.exists(filename):
                yield Rule(
                    "File owner",
                    11,
                    user == Audit.get_owner(filename),
                    10,
                    SEVERITY.CRITICAL.value,
                    "Files",
                    f"File owner is not {user}.",
                )

        for filename in simple_filenames:
            if path.exists(filename):
                yield Rule(
                    "File owner",
                    11,
                    user == Audit.get_owner(filename),
                    4,
                    SEVERITY.MEDIUM.value,
                    "Files",
                    f"File owner is not {user}.",
                )

    def get_permissions(filename: str) -> str:

        """This function return the file permissions."""

        return stat.filemode(os.stat(filename).st_mode)

    def audits_directory_permissions(
        server: Server, secure_paths: List[str] = None
    ) -> Iterator[Rule]:

        """
        This function check owner and permissions on bin directory.
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

        if secure_paths is None:
            config_path = path.join(server_path, "config")
            secure_paths = [
                path.join(sys.prefix, "bin"),
                config_path,
                path.join(config_path, "files"),
                path.join(config_path, "scripts"),
            ]

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
        This function check scripts timeout.
        """

        for script in server.pages.scripts.values():
            yield Rule(
                "Script timeout",
                35,
                script.timeout,
                7,
                SEVERITY.HIGH.value,
                "Script Configuration",
                f"The {script.name} timeout is not defined.",
            )

    def audits_file_rights(server: Server) -> Iterator[Rule]:

        """This function check the files rights."""

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

        current_dir = getcwd()

        rw_filenames = listdir(path.join(server_path, "data")) + listdir(
            "logs"
        )

        r_filenames = [
            path.join(server_path, "config", "server.ini"),
            path.join(server_path, "config", "server.json"),
        ]

        r_filenames.append(path.join(server_path, "config", "loggers.ini"))
        r_filenames.append(path.join(current_dir, "config", "server.ini"))
        r_filenames.append(path.join(current_dir, "config", "server.json"))

        for dirname in (server_path, current_dir):

            r_filenames += [
                file.path
                for file in server.pages.js_paths.values()
                if path.exists(file.path)
            ]

            r_filenames += [
                file.path
                for file in server.pages.statics_paths.values()
                if path.exists(file.path)
            ]

            executable_filenames = [
                script.path for script in server.pages.scripts.values()
            ]

        executable_filenames += [
            module.__file__
            for module in server.pages.packages.__dict__.values()
            if isinstance(module, ModuleType)
        ]

        yield from Audit.audits_directory_permissions(
            server,
            [
                path.dirname(path_)
                for path_ in executable_filenames + rw_filenames + r_filenames
                if path.exists(path_)
            ],
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
                f"File rights for {path.split(filename)[1]} is "
                "not 600 (rw- --- ---).",
            )
            for filename in rw_filenames
            if path.exists(filename)
        ]

        yield from [
            Rule(
                "File permissions (r--)",
                12,
                Audit.get_permissions(filename) == "-r--------",
                10,
                SEVERITY.CRITICAL.value,
                "Files",
                f"File rights for {path.split(filename)[1]} is "
                "not 400 (r-- --- ---).",
            )
            for filename in r_filenames
            if path.exists(filename)
        ]

        for filename in executable_filenames:
            if path.exists(filename):
                permissions = Audit.get_permissions(filename)

                yield Rule(
                    "File permissions (r-x)",
                    12,
                    permissions.endswith("------") and "w" not in permissions,
                    10,
                    SEVERITY.CRITICAL.value,
                    "Files",
                    f"File rights for {path.split(filename)[1]} is not 0 "
                    "for group and 0 for other (xxx --- ---).",
                )

    def audit_export_configuration(server: Server) -> Iterator[Rule]:

        """This function check the export configuration file."""

        return Rule(
            "Export file",
            13,
            not path.exists("export_Configuration.json"),
            3,
            SEVERITY.LOW.value,
            "Files",
            "The export configuration file exist, "
            "should be deleted on production.",
        )

    def log_rule(rule: Rule, logs: Logs) -> None:

        """This function log rule."""

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

        """This function run audit and checks."""

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

    def check_for_updates(
        configuration: ServerConfiguration, logs: Logs, send_mail: Callable
    ) -> None:

        """This function runs in a thread indefinitely, it checks the version
        and the latest published version of WebScripts every hour.
        If the version and the latest published version are different,
        this function sends an email notification."""

        latest = None
        latest_ = ""

        if __package__:
            version = sys.modules[__package__].__version__
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

            data = json.load(response)
            return data[0]["name"][1:]

        sleep(
            120
        )  # Wait 2 minutes (else "SmtpError: to many connections" is raised)

        while True:

            try:
                latest = get_latest()
            except URLError:
                logs.critical(
                    "Network error: the version of WebScripts is not checked."
                )
                break

            if version != latest and latest != latest_:
                logs.critical(
                    "WebScripts is not up-to-date, current:"
                    f" {version} latest: {latest}"
                )
                send_mail(
                    configuration,
                    f"Current WebScripts version: {version}\n"
                    f"Latest WebScripts version:  {latest}\nIt is "
                    "recommended that you upgrade your WebScripts server.",
                )

            latest_ = latest
            sleep(3600)


'''class FilesIntegity:

    """This class check the files integrity."""

    def __init__(self):
        self.

    def check_files_integrity(self):

        """"""

        with open("default_files.json") as file:
            files = json.load(file)

        for directory in ():
            for file, data in files:
                ...
'''


def main(server: Server, logs: Logs, send_mail: Callable) -> Report:

    """Main function to execute this file."""

    rules = Audit.run(server, logs)
    report = Report(rules, server, logs)
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

    logs.debug("Start a thread to check WebScripts version...")
    version = Thread(
        target=Audit.check_for_updates,
        args=(
            server.configuration,
            logs,
            send_mail,
        ),
        daemon=True,
    )
    version.start()

    return report
