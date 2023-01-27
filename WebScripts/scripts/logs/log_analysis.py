#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file displays an HTML table for log and activity analysis
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

This file displays an HTML table for log and activity analysis.
"""

__version__ = "1.1.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file displays an HTML table for log and activity analysis.
"""
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

__all__ = ["write_line", "write_csv", "main"]

from collections import Counter
from typing import Dict, List
from sys import exit, stdout
from os import environ
from csv import writer


def write_line(
    csv_writer: writer,
    date: str,
    dates: List[str],
    columns: List[str],
    table: Dict[str, Dict[str, int]],
) -> None:

    """
    This function creates an HTML table row.
    """

    if date not in dates:
        dates.add(date)
        csv_writer.writerow(
            [
                date[1:]
                if column == "date"
                else str(table[column].get(date, 0))
                for column in columns
            ]
        )


def write_csv(table: Dict[str, Dict[str, int]]) -> None:

    """
    This function builds the HTML table.
    """

    columns = ["date", *table.keys()]
    csv_writer = writer(stdout)
    csv_writer.writerow(columns)

    dates = set()

    for dates_ in table.values():
        for date in dates_.keys():
            write_line(csv_writer, date, dates, columns, table)


def main() -> int:

    """
    This function read the logfile and parse lines.
    """

    table = {}

    for level in environ["WEBSCRIPTS_LOGS_FILES"].split("|"):
        level, filename = level.split("?", 1)

        if level.casefold() == "all":
            break

    with open(filename) as logfile:
        readline = logfile.readline
        line = readline()

        while line != "":
            line = line.split(maxsplit=4)

            if len(line) == 5 and line[2] in (
                "DEBUG",
                "INFO",
                "ACCESS",
                "RESPONSE",
                "COMMAND",
                "WARNING",
                "ERROR",
                "CRITICAL",
            ):
                date, time, level, level_no, log = line
            else:
                line = readline()
                continue

            table_level = table.setdefault(level, Counter())
            table_level[date] += 1

            line = readline()

    write_csv(table)
    return 0


if __name__ == "__main__":
    exit(main())
