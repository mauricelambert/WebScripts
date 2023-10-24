#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool runs CLI scripts and displays output in a Web Interface.
#    Copyright (C) 2021, 2022, 2023  Maurice Lambert

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
This tool runs CLI scripts and displays output in a Web Interface.

This file implement error, report and request pages by default.
"""

from typing import Tuple, Dict, List, TypeVar, Any
from csv import reader, writer, QUOTE_ALL
from email.message import EmailMessage
from collections.abc import Iterator
from smtplib import SMTP, SMTP_SSL
from collections import namedtuple
from os import _Environ, path
from threading import Thread
from string import Template
from copy import deepcopy
from html import escape
from sys import modules
from json import dumps
from time import time

ServerConfiguration = TypeVar("ServerConfiguration")
Server = TypeVar("Server")
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

__version__ = "1.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file implement errors and report/request pages by default.
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
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

commons = modules.get("commons") or modules["WebScripts.commons"]
CallableFile = deepcopy(commons.CallableFile)
TokenCSRF = commons.TokenCSRF

template_script = CallableFile.template_script

script: str = """
            script_name = "/error_pages/Request/send/${code}";
            script =  {
                "content_type": "text/plain",
                "name": "/error_pages/Request/send/${code}",
                "category": "Error ${code}",
                "description": "${text}",
                "args": [
                    {
                        "input": false,
                        "name": "title",
                        "javascript_attributs": {},
                        "example": "Access/permissions",
                        "description": "The reason for your message."
                    },
                    {
                        "input": false,
                        "name": "request",
                        "javascript_attributs": {},
                        "example": "I need access to this script.",
                        "description": "Here your can describe your problem, administrators will read this message."
                    },
                    {
                        "input": false,
                        "name": "name",
                        "javascript_attributs": {},
                        "example": "Firstname LASTNAME",
                        description: "Your name to identify you"
                    },
                    {
                        "input": false,
                        "name": "error",
                        "html_type": "hidden",
                        "default_value": "${code}",
                        "javascript_attributs": {}
                    }
                ]
            };
            document.title = "Error ${code}";
            script = new Script(script);
            script.build_category();
            script.build_card("link_card", "script_cards", "category_content"); // "category"
            script.build_card("search_button", "search_result");
"""


def page_500(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    error: str,
) -> Tuple[str, Dict[str, str], List[bytes]]:
    """
    This function uses send_error_page to return the page 500 by default.
    """

    return send_error_page(environ, user, server, filename, error, "500")


def page_401(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    error: str,
) -> Tuple[str, Dict[str, str], List[bytes]]:
    """
    This function uses send_error_page to return the page 401 by default.
    """

    return send_error_page(environ, user, server, filename, error, "401")


def page_403(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    error: str,
) -> Tuple[str, Dict[str, str], List[bytes]]:
    """
    This function uses send_error_page to return the page 403 by default.
    """

    return send_error_page(environ, user, server, filename, error, "403")


def page_404(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    error: str,
) -> Tuple[str, Dict[str, str], List[bytes]]:
    """
    This function uses send_error_page to return the page 404 by default.
    """

    return send_error_page(environ, user, server, filename, error, "404")


def send_error_page(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    error: str,
    code: str,
    filepath: str = None,
) -> Tuple[str, Dict[str, str], List[bytes]]:
    """
    This function returns the default errors responses.
    """

    code = escape(code)

    CallableFile.template_script = template_script.replace(
        """script_name="%(name)s";""",
        script,
    )
    text = escape(filepath or ("Error " + code + " (" + error + ")"))
    error_page = CallableFile("script", __file__, text)
    _, headers, page = error_page(user, environ["SUB_DIRECTORIES_NUMBER"])
    page = Template(page)
    CallableFile.template_script = template_script

    return (
        error,
        headers,
        [
            page.substitute(code=code, text=text).encode("utf-8"),
        ],
    )


class Report:

    """
    This class implements pages for the report feature by default.
    """

    def new(
        environ: _Environ,
        user: User,
        server: Server,
        code: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function returns the report page by default.
        """

        return send_error_page(
            environ, user, server, code, "", code, "Report an error " + code
        )


class Request:

    """
    This class implements pages for the report feature by default.
    """

    def send_mail(
        configuration: ServerConfiguration,
        notification: str,
        title: str = "[! WebScripts Notification ]",
        content_type: str = None,
        attachments: List[Tuple[List[Any], Dict[str, Any]]] = [],
    ) -> None:
        """
        This function send a notification mail.

        Attachments is a list of tuple with args
        and kwargs of EmailMessage.add_attachment function.
        """

        server_name = getattr(configuration, "smtp_server", None)
        starttls = getattr(configuration, "smtp_starttls", None)
        password = getattr(configuration, "smtp_password", None)

        if not server_name:
            return None

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
            return None

        if password:
            server.login(configuration.email, password)

        email = EmailMessage()
        email.set_content(notification)
        email["To"] = ", ".join(configuration.admin_adresses)
        email["From"] = configuration.notification_address
        email["Subject"] = title

        if content_type is not None:
            email.replace_header("Content-Type", content_type)

        add_attachment = email.add_attachment
        for attachment_args, attachment_kwargs in attachments:
            add_attachment(
                *attachment_args,
                **attachment_kwargs,
            )

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
                reader(
                    open(filename, "r", newline=""),
                    quoting=QUOTE_ALL,
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
            csvfile = writer(file, quoting=QUOTE_ALL)
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
        server: Server,
        code: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function save and send request or report.
        """

        referer = escape(environ.get("HTTP_REFERER", ""))
        user_agent = escape(environ.get("HTTP_USER_AGENT", ""))
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
                server.configuration,
                notification,
            ),
        ).start()

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            dumps(
                {
                    "stdout": "Request or report sent successfully.",
                    "stderr": "",
                    "code": 0,
                    "Content-Type": "text/plain",
                    "Stderr-Content-Type": "text/plain",
                    "error": "No errors",
                    "csrf": TokenCSRF.build_token(user),
                }
            ),
        )
