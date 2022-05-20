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
from html import escape
from os import _Environ

Server = TypeVar("Server")
User = TypeVar("User")

notification_id: int = 0
NEW_LINE: str = "\n"


def add(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    arguments: List[str],
    inputs: List[str],
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:

    """
    This function adds a new notification
    in WebScripts pages.
    """

    server.CommonsClasses.CallableFile.template_header_path += f"""
        <p id="notification{notification_id}" class="notification">
            <span class="notification_user">{escape(user.name)}: </span>
            {escape(NEW_LINE.join(inputs))}
            <button class="notification_close">
                X
            </button>
        </p>
        <!--
            <p>.hidden=true;
            use SessionStorage to close automatically notifications
        -->
    """

    return (
        "200 OK",
        {"Content-Type": "text/plain"},
        "OK: notification is added.",
    )
