#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a HTML link to download a file
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

This file prints a HTML link to download a file.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file prints a HTML link to download a file"""
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

# from modules.uploads_management import get_file_content
from sys import argv, exit, stderr
from urllib.parse import quote
from html import escape


def main() -> int:

    """
    Print the HTML link to download the file or
    exit with an error code.
    """

    if len(argv) != 3:
        print(
            "USAGE: get_file.py [TYPE required string] "
            '[FILENAME required string]\n\t TYPE must be "ID" or "name"',
            file=stderr,
        )
        return 1

    _, type_, identifier = argv
    type_ = type_.lower()

    if type_ == "id":
        print(
            f"""
            <a href="/share/Download/id/{quote(identifier)}">
                Click here to download the file
            </a>
            """
        )
    elif type_ == "name":
        print(
            f"""
            <a href="/share/Download/filename/{quote(identifier)}">
                Click here to download the {escape(identifier)}
            </a>
            """
        )
    else:
        print('ERROR: TYPE must be "ID" or "name"', file=stderr)
        return 2

    # try:
    #     data, filename = get_file_content(name=name, id_=id_)
    # except Exception as e:
    #     print(escape(f"{e.__class__.__name__}: {e}"), file=stderr)
    #     exit(127)

    # print(
    #     f'<a href="data:application/octet-stream;base64, {data}" '
    #     f'download="{quote(filename)}">Click here to download '
    #     f"{escape(filename)}</a>"
    # )

    return 0


if __name__ == "__main__":
    exit(main())
