#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a web server to run scripts or executables
#    from the command line and display the result in a web interface.
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

This file implement a Content-Security-Policy debug page."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file implement a Content-Security-Policy debug page."""
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

from typing import Tuple, Dict, List, TypeVar
from error_pages import Request
from os import _Environ
import json

global csp_report

ServerConfiguration = TypeVar("ServerConfiguration")
User = TypeVar("User")

csp_report = {"report": "No CSP report yet."}


def debug(
    environ: _Environ,
    user: User,
    configuration: ServerConfiguration,
    code: str,
    arguments: Dict[str, Dict[str, str]],
    inputs: List[str],
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:

    """This function implement a debug page."""

    global csp_report

    if isinstance(arguments, dict):
        csp_report = arguments
        Request.send_mail(configuration, json.dumps(csp_report, indent=4))

    return (
        "200 OK",
        {
            "Content-Security-Policy": f"default-src 'self'; form-action 'none'; frame-ancestors 'none'",
            "Content-Type": "application/json; charset=utf-8",
        },
        json.dumps(csp_report, indent=4),
    )
