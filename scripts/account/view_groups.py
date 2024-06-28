#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints groups in a HTML table
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

This file prints groups in a HTML table.
"""

__version__ = "0.1.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file prints groups in a HTML table."""
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

__all__ = []

from modules.manage_defaults_databases import get_groups
from argparse import ArgumentParser, Namespace
from sys import stdout, exit, stderr
from csv import writer


def parse_args() -> Namespace:
    """
    This function parse command line arguments.
    """

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


def main() -> int:
    """
    Main function to print users using default manager for group database.
    """

    arguments = parse_args()

    for i, value in enumerate(arguments.ids):
        if not value.isdigit():
            print(
                f'ERROR: ids must be integer. "{value}"' " is not digits.",
                file=stderr,
            )
            return 3

    csv_writer = writer(stdout)

    for group in get_groups():
        if (
            (len(arguments.ids) == 0 and len(arguments.names) == 0)
            or (arguments.ids and group.ID in arguments.ids)
            or (arguments.names and group.name in arguments.names)
        ):
            csv_writer.writerow([group.ID, group.name])

    return 0


if __name__ == "__main__":
    exit(main())
