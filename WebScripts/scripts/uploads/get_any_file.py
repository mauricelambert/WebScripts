#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a HTML link to download a file
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

This file prints a HTML link to download a file."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file prints a HTML link to download a file"""
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

from modules.uploads_management import get_file_content
import sys


def main() -> None:

    """Print the HTML link to download the file or
    exit with an error code."""

    if len(sys.argv) != 3:
        print(
            "USAGE: get_file.py [TYPE required string] "
            '[FILENAME required string]\n\t TYPE must be "ID" or "name"'
        )
        sys.exit(1)

    _, type_, identifier = sys.argv
    type_ = type_.lower()

    if type_ == "id":
        id_, name = identifier, None
    elif type_ == "name":
        name, id_ = identifier, None
    else:
        print('ERROR: TYPE must be "ID" or "name"')
        sys.exit(2)

    try:
        data, filename = get_file_content(name=name, id_=id_)
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
        sys.exit(127)

    print(
        f'<a href="data:application/octet-stream;base64, {data}" '
        f'download="{filename}">Click here to download {filename}</a>'
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
