#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can display the latest logs
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

This file can display the latest logs.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file can display the latest logs.
"""
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

from sys import exit, stderr, argv
from collections import deque
from os import environ


def main() -> int:

    """
    Main function to display the latest logs.
    """

    length = len(argv) < 2 or argv[1]

    if not length or not length.isdigit():
        print(
            "USAGE: log_viewer.py [length required int] [level1 required "
            "string] [levelX optional string]..."
            "\n\tPossible values for files:\n\t\t - all\n\t\t - DEBUG\n\t\t"
            " - INFO\n\t\t - ACCESS\n\t\t - RESPONSE\n\t\t - WARNING"
            "\n\t\t - ERROR\n\t\t - CRITICAL\n\t\t - TRACE",
            file=stderr,
        )
        print(
            "ERROR: argument length is required and must be an "
            "integer, and a minimum of one level is required",
            file=stderr,
        )
        return 1

    length = int(length)
    del argv[1]
    del argv[0]

    levels = {}
    for level in environ["WEBSCRIPTS_LOGS_FILES"].split(":"):
        level, filename = level.split("|", 1)
        levels[level.casefold()] = filename

    for level in argv:
        filename = levels.get(level.casefold())

        if filename is None:
            continue

        argv.remove(level)
        with open(filename) as logfile:
            print("".join(deque(logfile, length)))

    if len(argv) != 0:
        print(f"ERROR: unexpected arguments {argv}", file=stderr)

    return 0


if __name__ == "__main__":
    exit(main())
