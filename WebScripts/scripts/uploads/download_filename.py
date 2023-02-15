#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a HTML link to download a file
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

This file prints a HTML link to download a file.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file prints a HTML link to download a file
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

__all__ = []

from modules.uploads_management import (
    #     read_file,
    get_file,
    check_permissions,
    get_user,
)
from sys import exit, argv, stderr
from urllib.parse import quote
from html import escape


def main() -> None:
    """
    This function prints the HTML link to download the file.
    """

    if len(argv) != 2:
        print("USAGES: get_file.py [FILENAME required string]", file=stderr)
        return 1

    filename = argv[1]

    uploads, counter = get_file(filename)

    if len(uploads) == 0:
        print(
            f"FileNotFoundError: No such file or directory: {filename}",
            file=stderr,
        )
        return 2

    file = uploads[-1]
    owner = get_user()
    try:
        check_permissions(file, owner, "read")
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}", file=stderr)
        return 127

    print(
        f'<a href="/share/Download/filename/{quote(filename)}">'
        f"Click here to download {escape(filename)}</a>"
    )

    return 0

    # try:
    #     data = read_file(filename)
    # except Exception as e:
    #     print(html.escape(f"{e.__class__.__name__}: {e}"))
    #     sys.exit(127)

    # print(
    #     f'<a href="data:application/octet-stream;base64, {data}" download="'
    #     f'{quote(filename)}">Click here to download '
    #     f"{html.escape(filename)}</a>"
    # )


if __name__ == "__main__":
    exit(main())
