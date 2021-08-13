#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can print users in HTML table
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

"""This package implements a web server to run scripts or 
executables from the command line and display the result 
in a web interface.

This file can print users in HTML table."""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file can print users in HTML table."""
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

from modules.manage_defaults_databases import get_users
from argparse import ArgumentParser, Namespace
import sys


def parse_args() -> Namespace:

    """This function parse command line arguments."""

    parser = ArgumentParser()
    parser.add_argument(
        "--ids",
        "-i",
        help="List of user IDs to display them only.",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "--names",
        "-n",
        help="List of user names to display them only.",
        nargs="+",
        default=[],
    )
    return parser.parse_args()


def main() -> None:

    """Main function to print users using default manager for user database."""

    arguments = parse_args()

    for i, value in enumerate(arguments.ids):
        if not value.isdigit():
            print(f'ERROR: ids must be integer. "{value}" is not digits.')
            sys.exit(3)

    print("<table>")

    for user in get_users():
        if (
            (len(arguments.ids) == 0 and len(arguments.names) == 0)
            or (arguments.ids and user.ID in arguments.ids)
            or (arguments.names and user.name in arguments.names)
        ):
            print(
                f"<tr><td>{user.ID}</td><td>{user.name}</td><td>{user.IPs}</td>"
                f"<td>{user.groups}</td><td>{user.apikey}</td><td>{user.categories}</td>"
                f"<td>{user.scripts}</td></tr>"
            )

    print("</table>")


if __name__ == "__main__":
    main()
    sys.exit(0)
