#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a user request
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

"""This tool run scripts and display the result in a Web Interface.

This file prints a user request."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file prints a user request"""
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

from modules.requests_management import get_request
from time import localtime, strftime
import sys


def main() -> None:

    """Print the user request."""

    if len(sys.argv) != 2:
        print("USAGES: python3 get_request.py ID")
        sys.exit(0)

    try:
        request = get_request(sys.argv[1])
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
        sys.exit(127)

    print(
        f'The user "{request.UserName}" get an error code {request.ErrorCode}'
        f' on "{request.Page}".\nThe user agent used '
        f'for the request creation is "{request.UserAgent}".\n'
        f"\nName: {request.Name}\nTime: "
        f"{strftime('%Y-%m-%d %H:%M:%S', localtime(float(request.Time)))}"
        f"\nSubject: {request.Subject}"
        f"\nReason: {request.Reason}"
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
