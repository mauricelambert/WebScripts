#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints an HTML table of uploaded files sizes.
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

This file prints an HTML table of uploaded files sizes.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file prints an HTML table of uploaded files sizes.
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

__all__ = ["main"]

from modules.uploads_management import get_metadata
from sys import exit


def main() -> int:
    """
    This function prints an HTML table of uploaded files sizes.
    """

    print(
        "<table><thead><tr><th>name</th><th>full size (all version)</th><th>"
        "size</th><th>Number of version</th><th>modification</th>"
        "<th>Creation (OS)</th><th>Creation (WebScripts)</th><th>Acces</th>"
        "</tr></thead><tbody>"
    )

    for name, metadata in get_metadata().items():
        print(
            f"<tr><td>{name}</td><td>{metadata.full_size}</td>"
            f"<td>{metadata.last_size}</td><td>{metadata.version}</td>"
            f"<td>{metadata.modification}</td><td>{metadata.creation}</td>"
            f"<td>{metadata.webscripts_creation}</td><td>{metadata.access}"
            "</td></tr>"
        )

    print("</tbody><tfoot></tfoot></table>")

    return 0


if __name__ == "__main__":
    exit(main())
