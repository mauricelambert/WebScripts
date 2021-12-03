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

"""
This tools run scripts and display the result in a Web Interface.

This file implement error, report and request pages by default.
"""

from typing import Tuple, Dict, List, TypeVar
from email.message import EmailMessage
from collections.abc import Iterator
from smtplib import SMTP, SMTP_SSL
from collections import namedtuple
from os import _Environ, path
from threading import Thread
from string import Template
from html import escape
from time import time
import secrets
import json
import csv

ServerConfiguration = TypeVar("ServerConfiguration")
User = TypeVar("User")

_Request = namedtuple(
    "_Request",
    [
        "ID",
        "Time",
        "UserName",
        "ErrorCode",
        "Page",
        "UserAgent",
        "Subject",
        "Reason",
        "Name",
    ],
)

__version__ = "0.0.4"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file implement errors and report/request pages by default."""
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

__all__ = [
    "page_500",
    "page_401",
    "page_403",
    "page_404",
    "Request",
    "Report",
]

page = Template(
    """
<!--

    HTML page to launch scripts.
    Copyright (C) 2021  Maurice Lambert

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

-->

<!DOCTYPE html>
<html>
    <head>
        <title>Error ${code}</title>
        <meta charset="utf-8">
        <link rel="shortcut icon" type="image/png" \
href="/static/webscripts_icon.png"/>
        <link rel="stylesheet" type="text/css" \
href="/static/webscripts_style.css">
        <link rel="stylesheet" type="text/css" \
href="/static/webscripts_script_style.css">
        <script type="text/javascript" src="/js/webscripts_js_scripts.js">
        </script>
        <script type="text/javascript" \
src="/js/webscripts_script_js_scripts.js">
        </script>
        <meta http-equiv="Content-Security-Policy" content="default-src \
'self'; form-action 'none'; script-src 'self' 'nonce-${nonce}'">
    </head>

    <body>
        <div class="center border">
            <span id="prevent_no_javascript">
                This WebApp requires JavaScript.
            </span>
        </div>

        <header id="webscripts_header" class="header border">
            <div id="webscripts_header_text_position">
                <h1 id="webscripts_title" class="title header border">
                    WebScripts Server
                </h1>

                <p id="webscripts_description" class="paragraph header border">
                    This server can help administrators,
                    SOC teams (Security Operations Center) and devops teams
                    to deploy faster some scripts, to share some
                    "console scripts" with people who have no particular
                    computer knowledge and share environnements of scripts
                    with their teams without install requirements on all
                    computers of the team.
                </p>
            </div>

            <div id="webscripts_header_image_position">
                <img id="webscripts_header_image" \
src="/static/webscripts_header.png">
            </div>
        </header>

        <div id="webscripts_border_left" class="border"></div>

        <div id="webscripts_content">
            <div id="script_presentation">
                <h1 id="script_title">Error ${code} - request or report</h1>
                <p class="description" id="script_description">
                    This script sends a request or a report to the
                    administrator of this Web server.
                </p>
                <a href="/web/auth/">Authentication</a>
                <a href="/web/">Index</a>
            </div>

            <p>${message}</p>

            <div id="script_interface">
                <div class="row">
                    <label for="title" class="inline script_presentation">
                        Subject:
                    </label>
                    <p class="inline description script_presentation">
                        subject of your request or report
                    </p>
                    <div class="input_wrapper inline">
                        <input id="title" name="title" type="text" \
placeholder="Access and permissions" class="default_theme">
                    </div>
                </div>

                <div class="row">
                    <label for="request" class="inline script_presentation">
                        Request or report:
                    </label>
                    <p class="inline description script_presentation">
                        message of your request or report
                    </p>
                    <div class="input_wrapper inline">
                        <input id="request" name="request" type="text" \
placeholder="I need access to this script." class="default_theme">
                    </div>
                </div>

                <div class="row">
                    <label for="name" class="inline script_presentation">
                        Your name:
                    </label>
                    <p class="inline description script_presentation">
                        Your name to identify you
                    </p>
                    <div class="input_wrapper inline">
                        <input id="name" name="name" type="text" \
placeholder="Firstname LASTNAME" class="default_theme">
                    </div>
                </div>

                <div id="submit_row" class="row">
                    <input type="hidden" id="error" name="error" \
value="${code}">
                    <input type="hidden" name="csrf_token" id="csrf_token" \
value="{csrf}">
                    <div class="submit_position">
                        <input id="submit_button" type="submit" class="submit"\
 value="Start script execution">
                    </div>
                </div>
            </div>

            <div id="progress_bar">
                <div id="bar">
                </div>
            </div>

            <div  id="script_outputs">

            </div>
        </div>

        <div id="webscripts_border_right" class="border"></div>

        <footer id="webscripts_footer" class="footer border">
            <ul id="webscripts_footer_list" class="list footer border">
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Source code and contact is
                    <a id="webscripts_link_source" \
href="https://github.com/mauricelambert/WebScripts">
                        here (on my github)
                    </a>.
                </li>
                <li id="webscripts_footer_list_wiki" \
class="bullet_point footer border">
                    Documentation is
                    <a id="webscripts_link_wiki" \
href="https://webscripts.readthedocs.io/en/latest/">
                        on readthedocs
                    </a> and
                    <a id="webscripts_link_wiki" \
href="https://github.com/mauricelambert/WebScripts/wiki">
                        on my github wiki
                    </a>.
                </li>
                <li id="webscripts_footer_list_wiki" \
class="bullet_point footer border">
                    License:
                    <a id="webscripts_link_wiki" \
href="https://www.gnu.org/licenses/">
                        GPL-3.0 License
                    </a>.
                </li>
            </ul>

            <ul id="webscripts_footer_list" class="list footer border">
                <li id="webscripts_footer_list_source" class="bullet_point \
footer border">
                    Pydoc documentation index:
                    <a id="webscripts_link_source" href="/static/index.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" href=\
"https://mauricelambert.github.io/info/python/code/WebScripts/index.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for WebScripts.py:
                    <a id="webscripts_link_source" \
href="/static/WebScripts.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" href=\
"https://mauricelambert.github.io/info/python/code/WebScripts/WebScripts.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for Pages.py:
                    <a id="webscripts_link_source" href="/static/Pages.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/Pages.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for commons.py:
                    <a id="webscripts_link_source" href="/static/commons.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/\
commons.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for utils.py:
                    <a id="webscripts_link_source" href="/static/utils.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/utils.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for Errors.py:
                    <a id="webscripts_link_source" href="/static/Errors.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/\
Errors.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for manage_defaults_databases.py:
                    <a id="webscripts_link_source" \
href="/static/manage_defaults_databases.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/\
manage_defaults_databases.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for uploads_management.py:
                    <a id="webscripts_link_source" \
href="/static/uploads_management.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/\
uploads_management.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for requests_management.py:
                    <a id="webscripts_link_source" \
href="/static/requests_management.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/\
requests_management.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for module error_pages.py:
                    <a id="webscripts_link_source" \
href="/static/error_pages.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/\
error_pages.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for module csp.py:
                    <a id="webscripts_link_source" href="/static/csp.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/csp.html">
                        online
                    </a>.
                </li>
                <li id="webscripts_footer_list_source" \
class="bullet_point footer border">
                    Pydoc documentation for module share.py:
                    <a id="webscripts_link_source" href="/static/share.html">
                        local
                    </a>,
                    <a id="webscripts_link_documentation" \
href="https://mauricelambert.github.io/info/python/code/WebScripts/share.html">
                        online
                    </a>.
                </li>
        </footer>

        <script type="text/javascript" nonce="${nonce}">
            document.getElementById("submit_button").onclick\
=start_script_execution;
            script_name="/error_pages/Request/send/${code}";
            document.getElementById("prevent_no_javascript").style.display\
='none';
            document.getElementById("webscripts_header_image").style.height = \
document.getElementById("webscripts_header_text_position").offsetHeight + "px";
            add_buttons();
            add_button();
            script =  {
                "content_type": "text/plain",
                "name": "/error_pages/request/${code}",
                "args": [
                    {
                        "input": false,
                        "name": "title"
                    },
                    {
                        "input": false,
                        "name": "request"
                    },
                    {
                        "input": false,
                        "name": "name"
                    },
                    {
                        "input": false,
                        "name": "error"
                    }
                ]
            };
        </script>
    </body>
</html>
"""
)


def page_500(error: str) -> Tuple[str, Dict[str, str], List[bytes]]:

    """
    This function uses send_error_page to return the page 500 by default.
    """

    return send_error_page(error, "500")


def page_401(error: str) -> Tuple[str, Dict[str, str], List[bytes]]:

    """
    This function uses send_error_page to return the page 401 by default.
    """

    return send_error_page(error, "401")


def page_403(error: str) -> Tuple[str, Dict[str, str], List[bytes]]:

    """
    This function uses send_error_page to return the page 403 by default.
    """

    return send_error_page(error, "403")


def page_404(error: str) -> Tuple[str, Dict[str, str], List[bytes]]:

    """
    This function uses send_error_page to return the page 404 by default.
    """

    return send_error_page(error, "404")


def send_error_page(
    error: str, code: str
) -> Tuple[str, Dict[str, str], List[bytes]]:

    """
    This function returns the default error code, headers and formatted pages.
    """

    nonce = secrets.token_hex(20)
    code = escape(code)
    return (
        error,
        {
            "Content-Security-Policy": (
                "default-src 'self'; form-action 'none'; frame-ancestors "
                f"'none'; script-src 'self' 'nonce-{nonce}'"
            ),
            "Content-Type": "text/html; charset=utf-8",
        },
        [
            page.substitute(code=code, nonce=nonce, message=error).encode(
                "utf-8"
            )
        ],
    )


class Report:

    """This class implements pages for the report feature by default."""

    def new(
        environ: _Environ,
        user: User,
        configuration: ServerConfiguration,
        code: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function returns the report page by default."""

        nonce = secrets.token_hex(20)
        code = escape(code)
        return (
            "200 OK",
            {
                "Content-Security-Policy": (
                    "default-src 'self'; form-action 'none'; frame-ancestors"
                    f" 'none'; script-src 'self' 'nonce-{nonce}'"
                ),
                "Content-Type": "text/html; charset=utf-8",
            },
            page.substitute(
                code=code, nonce=nonce, message=f"Report an error {code}"
            ),
        )


class Request:

    """This class implements pages for the report feature by default."""

    def send_mail(
        configuration: ServerConfiguration, notification: str
    ) -> None:

        """
        This function send a notification mail.
        """

        server_name = getattr(configuration, "smtp_server", None)
        starttls = getattr(configuration, "smtp_starttls", None)
        password = getattr(configuration, "smtp_password", None)

        if not server_name:
            return

        try:
            if starttls:
                server = SMTP(
                    server_name, getattr(configuration, "smtp_port", 587)
                )
            elif getattr(configuration, "smtp_ssl", None):
                server = SMTP_SSL(
                    server_name, getattr(configuration, "smtp_port", 465)
                )
            else:
                server = SMTP(
                    server_name, getattr(configuration, "smtp_port", 25)
                )
        except TimeoutError:
            return

        if password:
            server.login(configuration.email, password)

        email = EmailMessage()
        email.set_content(notification)
        email["To"] = ", ".join(configuration.admin_adresses)
        email["From"] = configuration.notification_address
        email["Subject"] = "[! WebScripts Notification ]"

        server.send_message(email)
        server.quit()

    def save(
        username: str,
        code: str,
        url: str,
        user_agent: str,
        subject: str,
        name: str,
        reason: str,
    ) -> None:

        """
        This function save the report/request to a CSV file.
        """

        filename = path.join(
            path.dirname(__file__), "..", "data", "requests.csv"
        )

        def get_requests() -> Iterator[_Request]:

            """
            This function build Request from database.
            """

            yield from map(
                _Request._make,
                csv.reader(
                    open(filename, "r", newline=""),
                    quoting=csv.QUOTE_ALL,
                ),
            )

        id_ = 0
        first = True
        for request in get_requests():
            if first:  # columns
                first = False
                continue
            id_ = int(request.ID) + 1

        with open(filename, "a", newline="") as file:
            csvfile = csv.writer(file, quoting=csv.QUOTE_ALL)
            csvfile.writerow(
                [
                    str(id_),
                    str(time()),
                    username,
                    code,
                    url,
                    user_agent,
                    subject,
                    name,
                    reason,
                ]
            )

    def send(
        environ: _Environ,
        user: User,
        configuration: ServerConfiguration,
        code: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function save and send request or report.
        """

        referer = escape(environ.get("HTTP_REFERER"))
        user_agent = escape(environ.get("HTTP_USER_AGENT"))
        subject = escape(arguments[0])
        name = escape(arguments[1])
        reason = escape(arguments[2])
        code = escape(code)
        user.name = escape(user.name)

        for string in (
            referer,
            user_agent,
            code,
            user.name,
            subject,
            name,
            reason,
        ):
            if not string.isprintable():
                raise ValueError(
                    f"Strings must be printable: '{string}' is not."
                )

        notification = (
            f'The user named: "{user.name}" get a HTTP error '
            f'code {code} on "{referer}" using "{user_agent}".'
            f'\nRequest or report from "{name}": \n\t'
            f"Subject: {subject} \n\tReason: {reason}"
        )

        Request.save(
            user.name, code, referer, user_agent, subject, name, reason
        )
        Thread(
            target=Request.send_mail,
            args=(
                configuration,
                notification,
            ),
        ).start()

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            json.dumps(
                {
                    "stdout": "Request or report sent successfully.",
                    "stderr": "",
                    "code": 0,
                    "Content-Type": "text/plain",
                    "Stderr-Content-Type": "text/plain",
                    "error": "No errors",
                    "csrf": "{csrf}",
                }
            ),
        )
