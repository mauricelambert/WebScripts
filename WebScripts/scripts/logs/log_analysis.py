#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file displays an HTML table for log and activity analysis
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

This file displays an HTML table for log and activity analysis."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file displays an HTML table for log and activity analysis."""
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

__all__ = ["get_line", "build_html_table", "main"]

from typing import Dict, List
from os import path, chdir
import sys


def get_line(
    date: str, dates: List[str], columns: List[str], table: Dict[str, Dict[str, int]]
) -> str:

    """This function creates an HTML table row."""

    line = ""

    if date not in dates:
        dates.append(date)
        line = "<tr>"
        for column in columns:
            if column == "date":
                line += f"<td>{date[1:]}</td>"
            else:
                log_number = table[column].get(date, 0)
                line += f"<td>{log_number}</td>"

        line += "</tr>"

    return line


def build_html_table(table: Dict[str, Dict[str, int]]) -> str:

    """This function builds the HTML table."""

    columns = ["date"] + list(table.keys())
    dates = []
    html = f"<table><tr><td>{'</td><td>'.join(columns)}</td></tr>"

    for dates_ in table.values():
        for date in dates_.keys():
            html += get_line(date, dates, columns, table)

    return html + "</table>"


def main() -> None:

    """This function read the logfile and parse lines."""

    chdir(path.join(path.dirname(__file__), "..", ".."))

    table = {}
    last_char = -1

    with open(path.join("logs", "00-server.logs")) as logfile:
        line = logfile.readline()

        while last_char != logfile.tell():
            line = line.split(maxsplit=3)

            if len(line) == 4 and line[2] in (
                "DEBUG(10)",
                "WARNING(30)",
                "INFO(20)",
                "ERROR(40)",
                "CRITICAL(50)",
            ):
                date, time, level, log = line
            else:
                line = logfile.readline()
                continue

            table.setdefault(level, {})
            table_level = table[level]
            table_level.setdefault(date, 0)
            table_level[date] += 1

            last_char = logfile.tell()
            line = logfile.readline()

    print(build_html_table(table))


if __name__ == "__main__":
    main()
    sys.exit(0)
