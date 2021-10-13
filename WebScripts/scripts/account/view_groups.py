#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints groups in a HTML table
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

This file prints groups in a HTML table."""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file prints groups in a HTML table."""
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

from modules.manage_defaults_databases import get_groups
from argparse import ArgumentParser, Namespace
import html
import sys


def parse_args() -> Namespace:

    """This function parse command line arguments."""

    parser = ArgumentParser()
    parser.add_argument(
        "--ids",
        "-i",
        help="List of group IDs to display them only.",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "--names",
        "-n",
        help="List of group names to display them only.",
        nargs="+",
        default=[],
    )
    return parser.parse_args()


def main() -> None:

    """
    Main function to print users using default manager for group database.
    """

    arguments = parse_args()

    for i, value in enumerate(arguments.ids):
        if not value.isdigit():
            print(
                f'ERROR: ids must be integer. "{html.escape(value)}"'
                " is not digits."
            )
            sys.exit(3)

    print("<table>")

    for group in get_groups():
        if (
            (len(arguments.ids) == 0 and len(arguments.names) == 0)
            or (arguments.ids and group.ID in arguments.ids)
            or (arguments.names and group.name in arguments.names)
        ):
            print(
                f"<tr><td>{html.escape(group.ID)}</td>"
                f"<td>{html.escape(group.name)}</td></tr>"
            )

    print("</table>")


if __name__ == "__main__":
    main()
    sys.exit(0)
