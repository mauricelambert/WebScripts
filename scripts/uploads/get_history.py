#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a HTML table of uploaded file versions
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

This file prints a HTML table of uploaded file versions.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file prints a HTML table of uploaded file versions.
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

__all__ = []

from modules.uploads_management import get_file
from time import localtime, strftime
from sys import argv, exit, stderr
from urllib.parse import quote
from html import escape


def main() -> int:

    """
    Print the HTML table of file history.
    """

    if len(argv) != 2:
        print("USAGE: get_history.py [FILENAME required string]")
        return 1

    filename = argv[1]

    fields = [
        "ID",
        "name",
        "read_permission",
        "write_permission",
        "delete_permission",
        "hidden",
        "is_deleted",
        "is_binary",
        "timestamp",
        "user",
        "version",
    ]
    print(
        f"<table><thead><tr><th>{'</th><th>'.join(fields)}"
        "</th></tr></thead><tbody>"
    )

    try:
        files, counter = get_file(filename)
    except Exception as e:
        print(escape(f"{e.__class__.__name__}: {e}"), file=stderr)
        return 127

    for file in files:
        file = file._replace(
            ID='<a href="/share/Download/id/'
            f'{quote(file.ID)}">{escape(file.ID)}</a>',
            timestamp=strftime(
                "%Y-%m-%d %H:%M:%S", localtime(float(file.timestamp))
            ),
        )
        print(
            f'<tr><td>{"</td><td>".join([escape(x) for x in file])}'
            "</td></tr>"
        )

    print("</tbody><tfoot></tfoot></table>")

    return 0


if __name__ == "__main__":
    exit(main())
