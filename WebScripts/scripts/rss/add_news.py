#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file adds a news in the RSS feed
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

This file adds a news in the RSS feed
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file adds a news in the RSS feed
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

__all__ = ["parse_args", "main", "get_guid"]

from argparse import ArgumentParser, Namespace
from csv import writer, reader, QUOTE_ALL
from sys import exit, stdin, stderr
from os.path import join, exists
from os import environ
from json import loads
from enum import Enum
from time import time


class FIELDS(Enum):
    guid = 0
    author = 1
    title = 2
    description = 3
    link = 4
    categories = 5
    pubDate = 6
    comments = 7


def parse_args() -> Namespace:

    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(
        description="This file adds a news in the RSS feed"
    )
    add_argument = parser.add_argument

    add_argument("title", help="The news title")
    add_argument("link", help="The news link (with the complete content)")
    add_argument(
        "categories",
        action="extend",
        nargs="+",
        help="The news categories (for filters)",
    )

    add_argument("-c", "--comments", help="The news comments", default="")

    return parser.parse_args()


def get_guid(csvpath: str) -> int:

    """
    This function returns the new GUID.
    """

    with open(csvpath, "r", newline="") as file:
        csvfile = reader(file)

        for line in csvfile:
            pass

    return csvfile.line_num


def main() -> int:

    """
    The main function to add the news in RSS feed.
    """

    arguments = parse_args()

    csvpath = join(environ["WEBSCRIPTS_DATA_PATH"], "rss.csv")

    if not exists(csvpath):
        print("FileNotFoundError: WEBSCRIPTS_DATA_PATH/rss.csv", file=stderr)
        return 2

    with open(csvpath, "a", newline="") as file:
        csvwriter = writer(file, quoting=QUOTE_ALL)
        csvwriter.writerow(
            (
                get_guid(csvpath),
                loads(environ["USER"])["name"],
                arguments.title,
                stdin.read(),
                arguments.link,
                ",".join(arguments.categories),
                str(time()),
                arguments.comments,
            )
        )

    return 0


if __name__ == "__main__":
    exit(main())
