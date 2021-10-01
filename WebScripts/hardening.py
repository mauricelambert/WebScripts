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

This file implement the hardening audit of the WebScripts installation and configuration."""

from email.message import EmailMessage
from os import getcwd, path, listdir
from collections.abc import Iterator
from smtplib import SMTP, SMTP_SSL
from dataclasses import dataclass
from socket import gethostbyname
from typing import TypeVar, List
from contextlib import suppress
from types import ModuleType
from threading import Thread
from getpass import getuser
from enum import Enum
import platform
import ctypes
import json
import stat
import sys
import os

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This tools run scripts and display the result in a Web Interface.

This file implement the hardening audit of the WebScripts installation and configuration."""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = ["Report", "Rule", "Audit", "SEVERITY", "main"]

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

    def as_json(self) -> str:

        """This function returns a JSON string of audit results."""

        self.reports_dict = {
            SEVERITY.INFORMATION.value: [],
            SEVERITY.LOW.value: [],
            SEVERITY.MEDIUM.value: [],
            SEVERITY.HIGH.value: [],
            SEVERITY.CRITICAL.value: [],
            "FAIL": [],
            "ALL": [],
            "SCORING": {
                "total": 0,
                "fail": 0,
                f"{SEVERITY.INFORMATION.value} total": 0,
                f"{SEVERITY.INFORMATION.value} fail": 0,
                f"{SEVERITY.LOW.value} total": 0,
                f"{SEVERITY.LOW.value} fail": 0,
                f"{SEVERITY.MEDIUM.value} total": 0,
                f"{SEVERITY.MEDIUM.value} fail": 0,
                f"{SEVERITY.HIGH.value} total": 0,
                f"{SEVERITY.HIGH.value} fail": 0,
                f"{SEVERITY.CRITICAL.value} total": 0,
                f"{SEVERITY.CRITICAL.value} fail": 0,
            },
            "fields": [],
        }
        for rule in self.rules:

            audit = {}
            self.reports_dict["ALL"].append(audit)
            self.reports_dict[rule.severity].append(audit)
            self.reports_dict["SCORING"]["total"] += rule.level
            self.reports_dict["SCORING"][f"{rule.severity} total"] += rule.level

            if not rule.is_OK:
                self.reports_dict["FAIL"].append(audit)
                self.reports_dict["SCORING"]["fail"] += rule.level
                self.reports_dict["SCORING"][f"{rule.severity} fail"] += rule.level

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

                if new_attribut not in self.reports_dict["fields"]:
                    self.reports_dict["fields"].append(new_attribut)

                audit[new_attribut] = new_value

        fields = self.reports_dict.pop("fields")
        self.reports_json = json.dumps(self.reports_dict, indent=4)
        self.reports_dict["fields"] = fields
        return self.reports_json

    def as_html(self) -> str:

        """This function return a HTML string of audit results."""

        if self.reports_dict is None:
            self.as_json()

        table_fail = (
            f"<tr><td>{'</td><td>'.join(self.reports_dict['fields'])}</td></tr>"
        )
        for rule in self.reports_dict["FAIL"]:
            class_HTML = f'class="{rule["severity"].lower()}"'
            table_fail += f"<tr><td {class_HTML}>{f'</td><td {class_HTML}>'.join(str(x) for x in rule.values())}</td></tr>"

        table_critical = (
            f"<tr><td>{'</td><td>'.join(self.reports_dict['fields'])}</td></tr>"
        )
        for rule in self.reports_dict[SEVERITY.CRITICAL.value]:
            class_HTML = f'class="{rule["severity"].lower()}"'
            table_critical += f"<tr><td {class_HTML}>{f'</td><td {class_HTML}>'.join(str(x) for x in rule.values())}</td></tr>"

        table_high = (
            f"<tr><td>{'</td><td>'.join(self.reports_dict['fields'])}</td></tr>"
        )
        for rule in self.reports_dict[SEVERITY.HIGH.value]:
            class_HTML = f'class="{rule["severity"].lower()}"'
            table_high += f"<tr><td {class_HTML}>{f'</td><td {class_HTML}>'.join(str(x) for x in rule.values())}</td></tr>"

        table_medium = (
            f"<tr><td>{'</td><td>'.join(self.reports_dict['fields'])}</td></tr>"
        )
        for rule in self.reports_dict[SEVERITY.MEDIUM.value]:
            class_HTML = f'class="{rule["severity"].lower()}"'
            table_medium += f"<tr><td {class_HTML}>{f'</td><td {class_HTML}>'.join(str(x) for x in rule.values())}</td></tr>"

        table_low = f"<tr><td>{'</td><td>'.join(self.reports_dict['fields'])}</td></tr>"
        for rule in self.reports_dict[SEVERITY.LOW.value]:
            class_HTML = f'class="{rule["severity"].lower()}"'
            table_low += f"<tr><td {class_HTML}>{f'</td><td {class_HTML}>'.join(str(x) for x in rule.values())}</td></tr>"

        table_information = (
            f"<tr><td>{'</td><td>'.join(self.reports_dict['fields'])}</td></tr>"
        )
        for rule in self.reports_dict[SEVERITY.INFORMATION.value]:
            class_HTML = f'class="{rule["severity"].lower()}"'
            table_information += f"<tr><td {class_HTML}>{f'</td><td {class_HTML}>'.join(str(x) for x in rule.values())}</td></tr>"

        self.reports_html = f"""
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>WebScripts audit</title>
        <style type="text/css">
            html, body {{width: 100%; background-color: #222222;}}
            h1 {{text-align: center;}}
            h1, h2, p, table, tr, td, li, ul, a {{color: #ffc26a; font-family : Arial, Helvetica, "Liberation Sans", FreeSans, sans-serif;}}
            tr, td {{margin: 0.5%; padding: 1%; padding-left: 0.1%; color: #b16b05; border: 1px solid #b16b05;}}
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
            <tr><td>Score</td><td>Fail</td><td>Total</td><td>Compliance (% pourcent)</td></tr>
            <tr><td>All</td><td>{self.reports_dict["SCORING"]["fail"]}</td><td>{self.reports_dict["SCORING"]["total"]}</td><td>{100 - self.reports_dict["SCORING"]["fail"] * 100 / self.reports_dict["SCORING"]["total"]}</td></tr>
            <tr><td class="critical">Critical</td><td class="critical">{self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} fail"]}</td><td class="critical">{self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} total"]}</td><td class="critical">{100 - self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} total"]}</td></tr>
            <tr><td class="high">High</td><td class="high">{self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} fail"]}</td><td class="high">{self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} total"]}</td><td class="high">{100 - self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} total"]}</td></tr>
            <tr><td class="medium">Medium</td><td class="medium">{self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} fail"]}</td><td class="medium">{self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} total"]}</td><td class="medium">{100 - self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} total"]}</td></tr>
            <tr><td class="low">Low</td><td class="low">{self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} fail"]}</td><td class="low">{self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} total"]}</td><td class="low">{100 - self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} total"]}</td></tr>
            <tr><td class="information">Information</td><td class="information">{self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} fail"]}</td><td class="information">{self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} total"]}</td><td class="information">{100 - self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} total"]}</td></tr>
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

    def as_text(self) -> str:

        """This function return a HTML string of audit results."""

        if self.reports_dict is None:
            self.as_json()

        tab = "\t"
        end = "..."
        fail_text = "    - " + "\n    - ".join(
            [
                f"{''.join(f'{attribut}:{value if not isinstance(value, str) or len(value) < (10 + len(end)) else value[:10] + end},{tab}' for attribut, value in rule.items())}"
                for rule in self.reports_dict["FAIL"]
            ]
        )
        critical_text = "    - " + "\n    - ".join(
            [
                f"{''.join(f'{attribut}:{value if not isinstance(value, str) or len(value) < (10 + len(end)) else value[:10] + end},{tab}' for attribut, value in rule.items())}"
                for rule in self.reports_dict[SEVERITY.CRITICAL.value]
            ]
        )
        high_text = "    - " + "\n    - ".join(
            [
                f"{''.join(f'{attribut}:{value if not isinstance(value, str) or len(value) < (10 + len(end)) else value[:10] + end},{tab}' for attribut, value in rule.items())}"
                for rule in self.reports_dict[SEVERITY.HIGH.value]
            ]
        )
        medium_text = "    - " + "\n    - ".join(
            [
                f"{''.join(f'{attribut}:{value if not isinstance(value, str) or len(value) < (10 + len(end)) else value[:10] + end},{tab}' for attribut, value in rule.items())}"
                for rule in self.reports_dict[SEVERITY.MEDIUM.value]
            ]
        )
        low_text = "    - " + "\n    - ".join(
            [
                f"{''.join(f'{attribut}:{value if not isinstance(value, str) or len(value) < (10 + len(end)) else value[:10] + end},{tab}' for attribut, value in rule.items())}"
                for rule in self.reports_dict[SEVERITY.LOW.value]
            ]
        )
        information_text = "    - " + "\n    - ".join(
            [
                f"{''.join(f'{attribut}:{value if not isinstance(value, str) or len(value) < (10 + len(end)) else value[:10] + end},{tab}' for attribut, value in rule.items())}"
                for rule in self.reports_dict[SEVERITY.INFORMATION.value]
            ]
        )

        self.reports_text = f"""
     ___________________________________________
    |                                           |
    |  ** WebScripts Hardening Audit Report **  |
    |___________________________________________|
 
 1. Scoring
    - ALL:         Total:\t{self.reports_dict["SCORING"]["total"]},\t Fail:\t{self.reports_dict["SCORING"]["fail"]},\t Pourcent:\t{100 - self.reports_dict["SCORING"]["fail"] * 100 / self.reports_dict["SCORING"]["total"]}%
    - CRITICAL:    Total:\t{self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} fail"]},\t Fail:\t{self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} fail"]},\t Pourcent:\t{100 - self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.CRITICAL.value} total"]}%
    - HIGH:       Total:\t{self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} fail"]},\t Fail:\t{self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} fail"]},\t Pourcent:\t{100 - self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.HIGH.value} total"]}%
    - MEDIUM:      Total:\t{self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} fail"]},\t Fail:\t{self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} fail"]},\t Pourcent:\t{100 - self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.MEDIUM.value} total"]}%
    - LOW:         Total:\t{self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} fail"]},\t Fail:\t{self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} fail"]},\t Pourcent:\t{100 - self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.LOW.value} total"]}%
    - INFORMATION: Total:\t{self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} fail"]},\t Fail:\t{self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} fail"]},\t Pourcent:\t{100 - self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} fail"] * 100 / self.reports_dict["SCORING"][f"{SEVERITY.INFORMATION.value} total"]}%

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

        try:
            if starttls:
                server = SMTP(
                    server_name, getattr(self.server.configuration, "smtp_port", 587)
                )
            elif getattr(self.server.configuration, "smtp_ssl", None):
                server = SMTP_SSL(
                    server_name, getattr(self.server.configuration, "smtp_port", 465)
                )
            else:
                server = SMTP(
                    server_name, getattr(self.server.configuration, "smtp_port", 25)
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

    def audit_system_user(server: Server) -> Rule:

        """This function check the user."""

        if platform.system() == "Windows":
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
            SEVERITY.MEDIUM.value,
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
            or (server.configuration.smtp_starttls or server.configuration.smtp_ssl),
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
                7,
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

        """This function check the configuration of the script stderr content type."""

        for script in server.pages.scripts.values():
            yield Rule(
                "Error content type",
                9,
                script.stderr_content_type == "text/plain",
                8,
                SEVERITY.CRITICAL.value,
                "Script Configuration",
                f"The content type of the stderr for {script.name} is not text/plain.",
            )

    def audits_scripts_content_type(server: Server) -> Iterator[Rule]:

        """This function check the configuration of the script content type."""

        for script in server.pages.scripts.values():
            yield Rule(
                "Output content type",
                10,
                script.content_type == "text/plain",
                1,
                SEVERITY.INFORMATION.value,
                "Script Configuration",
                f"The content type of the script named {script.name} is not text/plain.",
            )

    def audits_scripts_path(server: Server) -> Iterator[Rule]:

        """This function check the configuration of the script path."""

        for script in server.pages.scripts.values():
            yield Rule(
                "Script path",
                17,
                script.path_is_defined and path.isabs(script.path),
                7,
                SEVERITY.MEDIUM.value,
                "Script Configuration",
                f"The path of {script.name} is not defined in configuration files or is not absolute.",
            )

            delattr(script, "path_is_defined")

    def audits_launcher(server: Server) -> Iterator[Rule]:

        """This function check the configuration of the script launcher."""

        for script in server.pages.scripts.values():
            yield Rule(
                "Script launcher",
                18,
                path.isabs(script.launcher),
                7,
                SEVERITY.MEDIUM.value,
                "Script Configuration",
                f"The path of {script.name} launcher is not absolute.",
            )

    def audit_admin_account(server: Server) -> Iterator[Rule]:

        """This function check the admin password."""

        default_password = False

        with open(path.join(server_path, "data", "users.csv")) as file:
            line = file.readline()

            while line:
                if (
                    "pZo8c8+cKLTHFaUBxGwcYaFDgNRw9HHph4brixOo6OMusFKbfkBEObZiNwda/f9W3+IpiMY8kqiFmQcbkUCbGw=="
                    in line
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

        if platform.system() == "Windows":
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

        if platform.system() == "Windows":
            important_filenames = [
                path.join(server_path, "config", "nt", "server.ini"),
                path.join(server_path, "config", "nt", "server.json"),
            ]
        else:
            important_filenames = [
                path.join(server_path, "config", "server.ini"),
                path.join(server_path, "config", "server.json"),
            ]

        important_filenames.append(path.join(server_path, "config", "loggers.ini"))
        important_filenames.append(path.join(current_dir, "config", "server.ini"))
        important_filenames.append(path.join(current_dir, "config", "server.json"))

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

    def audits_file_rights(server: Server) -> Iterator[Rule]:

        """This function check the files rights."""

        if platform.system() == "Windows":
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

        executable_filenames = []

        rw_filenames = [
            path.join(server_path, "config", "server.ini"),
            path.join(server_path, "config", "server.json"),
        ]

        rw_filenames.append(path.join(server_path, "config", "loggers.ini"))
        rw_filenames.append(path.join(current_dir, "config", "server.ini"))
        rw_filenames.append(path.join(current_dir, "config", "server.json"))

        rw_filenames += listdir("logs")
        rw_filenames += listdir(path.join(server_path, "data"))

        for dirname in (server_path, current_dir):

            for file in server.pages.js_paths.values():
                if path.exists(file.path):
                    rw_filenames.append(file.path)

            for file in server.pages.statics_paths.values():
                if path.exists(file.path):
                    rw_filenames.append(file.path)

        for script in server.pages.scripts.values():
            executable_filenames.append(script.path)

        for module in server.pages.packages.__dict__.values():
            if isinstance(module, ModuleType):
                executable_filenames.append(module.__file__)

        for filename in rw_filenames:
            if path.exists(filename):
                yield Rule(
                    "File permissions",
                    12,
                    "-rw-------" == Audit.get_permissions(filename),
                    10,
                    SEVERITY.CRITICAL.value,
                    "Files",
                    f"File rights for {path.split(filename)[1]} is not 600 (rw- --- ---).",
                )

        for filename in executable_filenames:
            if path.exists(filename):
                yield Rule(
                    "File permissions",
                    12,
                    Audit.get_permissions(filename).endswith("------"),
                    10,
                    SEVERITY.CRITICAL.value,
                    "Files",
                    f"File rights for {path.split(filename)[1]} is not 0 for group and 0 for other (xxx --- ---).",
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
            "The export configuration file exist, should be deleted on production.",
        )

    def log_rule(rule: Rule, logs: Logs) -> None:

        """This function log rule."""

        if rule.is_OK:
            state = "PASS"
        else:
            state = "FAIL"

        log = (
            f"Audit -> state: {state}, ID: {rule.id_}, severity: {rule.severity}, level: {rule.level}, "
            f'category: {rule.category}, subject: "{rule.subject}", reason: "{rule.reason}".'
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


def main(server: Server, logs: Logs) -> Report:

    """Main function to execute this file."""

    rules = Audit.run(server, logs)
    report = Report(rules, server, logs)
    report.as_json()
    report.as_html()
    report.as_text()

    with open("audit.json", "w") as file:
        file.write(report.reports_json)

    with open("audit.html", "w") as file:
        file.write(report.reports_html)

    with open("audit.txt", "w") as file:
        file.write(report.reports_text)

    Thread(target=report.notification).start()

    return report
