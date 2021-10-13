#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can display the latest logs
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

This file can display the latest logs."""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file can display the latest logs."""
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

from collections import deque
from os import path  # , chdir
import sys


def main() -> None:

    """Main function to display the latest logs."""

    # chdir(path.join(path.dirname(__file__), "..", ".."))

    if len(sys.argv) < 2 or not sys.argv[1].isdigit():
        print(
            "USAGE: log_viewer.py [length required int] [file1 required "
            "string] [fileX optional string]..."
            "\n\tPossible values for files:\n\t\t - all\n\t\t - DEBUG\n\t\t"
            " - INFO\n\t\t - WARNING"
            "\n\t\t - ERROR\n\t\t - CRITICAL"
        )
        print(
            "ERROR: argument length is required and must be an "
            "integer, and a minimum file is required"
        )
        sys.exit(1)

    length = int(sys.argv[1])
    del sys.argv[1]

    if "all" in sys.argv:
        sys.argv.remove("all")
        with open(path.join("logs", "00-server.logs")) as logfile:
            print("".join(deque(logfile, length)))

    if "DEBUG" in sys.argv:
        sys.argv.remove("DEBUG")
        with open(path.join("logs", "10-debug.logs")) as logfile:
            print("".join(deque(logfile, length)))

    if "INFO" in sys.argv:
        sys.argv.remove("INFO")
        with open(path.join("logs", "20-info.logs")) as logfile:
            print("".join(deque(logfile, length)))

    if "WARNING" in sys.argv:
        sys.argv.remove("WARNING")
        with open(path.join("logs", "30-warning.logs")) as logfile:
            print("".join(deque(logfile, length)))

    if "ERROR" in sys.argv:
        sys.argv.remove("ERROR")
        with open(path.join("logs", "40-error.logs")) as logfile:
            print("".join(deque(logfile, length)))

    if "CRITICAL" in sys.argv:
        sys.argv.remove("CRITICAL")
        with open(path.join("logs", "50-critical.logs")) as logfile:
            print("".join(deque(logfile, length)))

    if len(sys.argv) > 1:
        print(f"ERROR: unexpected arguments {sys.argv[1:]}")


if __name__ == "__main__":
    main()
    sys.exit(0)
