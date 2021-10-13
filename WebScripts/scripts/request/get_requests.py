#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a HTML table of user requests
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

This file prints an HTML table of user requests."""

__version__ = "0.1.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file prints a HTML table of user requests"""
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

__all__ = []

from modules.requests_management import get_requests
from time import localtime, strftime
from urllib.parse import quote
import html
import sys


def main() -> None:

    """Print the HTML table of user requests."""

    fields = [
        "ID",
        "Time",
        "UserName",
        "Subject",
        "ErrorCode",
        "Page",
    ]
    print(f"<table><tr><td>{'</td><td>'.join(fields)}</td></tr>")

    try:
        requests = get_requests()
    except Exception as e:
        print(html.escape(f"{e.__class__.__name__}: {e}"))
        sys.exit(127)

    not_first = False
    for request in requests:
        if not_first:
            print(
                f'<tr><td><a href="get_request.py?ID={quote(request.ID)}">'
                f"{html.escape(request.ID)}</a></td><td>"
                + strftime("%Y-%m-%d %H:%M:%S", localtime(float(request.Time)))
                + f"</td><td>{html.escape(request.UserName)}</td>"
                f"<td>{html.escape(request.Subject)}</td>"
                f"<td>{html.escape(request.ErrorCode)}</td>"
                f"<td>{html.escape(request.Page)}</td></tr>"
            )
        else:
            not_first = True

    print("</table>")


if __name__ == "__main__":
    main()
    sys.exit(0)
