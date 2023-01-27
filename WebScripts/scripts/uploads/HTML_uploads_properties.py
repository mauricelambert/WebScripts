#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints an HTML table of uploaded files sizes.
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

This file prints an HTML table of uploaded files sizes.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file prints an HTML table of uploaded files sizes.
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

__all__ = ["main"]

from modules.uploads_management import get_metadata
from datetime import datetime
from sys import exit, stdout
from csv import writer

fromtimestamp = datetime.fromtimestamp


def main() -> int:

    """
    This function prints an HTML table of uploaded files sizes.
    """

    csv_write = writer(stdout)
    csv_write.writerow(
        [
            "Name",
            "Full size (ko) (all versions)",
            "Size (ko)",
            "Number of version",
            "Date modification",
            "Date creation (OS)",
            "Date creation (WebScripts)",
            "Date acces",
        ]
    )

    for name, metadata in get_metadata().items():
        csv_write.writerow(
            [
                name,
                str(metadata.full_size / 1000),
                str(metadata.last_size / 1000),
                metadata.version,
                fromtimestamp(metadata.modification).strftime(
                    "%Y-%d-%d %H:%M:%S"
                ),
                fromtimestamp(metadata.creation).strftime("%Y-%d-%d %H:%M:%S"),
                fromtimestamp(metadata.webscripts_creation).strftime(
                    "%Y-%d-%d %H:%M:%S"
                ),
                fromtimestamp(metadata.access).strftime("%Y-%d-%d %H:%M:%S"),
            ]
        )

    return 0


if __name__ == "__main__":
    exit(main())
