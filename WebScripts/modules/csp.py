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

This file implements a Content-Security-Policy debug page.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file implements a Content-Security-Policy debug page.
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

from typing import Tuple, Dict, List, TypeVar
from json.decoder import JSONDecodeError
from error_pages import Request
from json import dumps, loads
from os import _Environ

global csp_report

Server = TypeVar("Server")
User = TypeVar("User")

csp_report = {"report": "No CSP report yet."}


def debug(
    environ: _Environ,
    user: User,
    server: Server,
    code: str,
    arguments: Dict[str, Dict[str, str]],
    inputs: List[str],
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:
    """
    This function implements a debug page.
    """

    global csp_report

    if isinstance(arguments, bytes):
        try:
            csp_report = loads(arguments)
        except JSONDecodeError:
            pass
        else:
            Request.send_mail(
                server.configuration, dumps(csp_report, indent=4)
            )

    return (
        "200 OK",
        {
            "Content-Security-Policy": (
                "default-src 'self'; form-action 'none'; "
                "frame-ancestors 'none'"
            ),
            "Content-Type": "application/json; charset=utf-8",
        },
        dumps(csp_report, indent=4),
    )
