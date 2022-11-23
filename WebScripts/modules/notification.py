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

This module adds notifications on WebScripts pages.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This module adds notifications on WebScripts pages.
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = ["add"]

from typing import TypeVar, List, Tuple, Dict
from urllib.parse import parse_qs
from types import MethodType
from html import escape
from os import _Environ
from sys import modules

Server = TypeVar("Server")
User = TypeVar("User")

notification_id: int = 0

module_getter: MethodType = modules.get
check_right = module_getter(
    "WebScripts.Pages"
    if module_getter("WebScripts")
    else "WebScripts38.Pages",
    module_getter("Pages"),
).check_right
commons = module_getter("commons") or modules["WebScripts.commons"]
TokenCSRF = commons.TokenCSRF


def add(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    arguments: bytes,
    inputs: List[str],
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:

    """
    This function adds a new notification
    in WebScripts pages.
    """

    global notification_id
    script = server.pages.scripts.get("change_user_password.py")
    permissions = getattr(server.configuration, "admin_groups", None)

    if script and not check_right(user, script):
        return "403", {}, b""
    elif permissions and not any(g in permissions for g in user["groups"]):
        return "403", {}, b""

    if arguments:
        form = parse_qs(arguments.decode())
        environ_getter = environ.get
        text = form.get("text")
        if text and TokenCSRF.check_csrf(
            user,
            form.get("csrf", [None])[0],
            getattr(server.configuration, "csrf_max_time", 300),
            environ_getter("HTTP_REFERER"),
            server.get_baseurl(environ_getter, environ),
        ):
            server.CommonsClasses.CallableFile.template_header += f"""
                <div id="notification{notification_id}" class="notification">
                    <button class="notification_close">
                        &#9932; Close
                    </button>
                    <p>
                        <span class="notification_user">{escape(user.name)}:\
 </span>
                        {escape(text[0])}
                    </p>
                </div>
            """
            notification_id += 1
    else:
        return (
            "200 OK",
            {
                "Content-Security-Policy": server.headers[
                    "Content-Security-Policy"
                ].replace("form-action 'none';", "form-action 'self';")
            },
            f"""
            <html>
                <head>
                </head>
                <body>
                    <form action="" method="POST">
                        <textarea name="text"></textarea>
                        <input type="hidden" name="csrf"\
 value="{TokenCSRF.build_token(user)}">
                        <input type="submit">
                    </form>
                </body>
            </html>
        """,
        )

    return (
        "200 OK",
        {"Content-Type": "text/plain"},
        "OK: notification is added.",
    )
