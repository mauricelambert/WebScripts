#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a HTML table of uploaded files
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

This file prints a HTML table of uploaded files."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file prints a HTML table of uploaded files"""
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

from modules.uploads_management import get_files
import sys


def main() -> None:

    """Print the HTML table of uploaded files."""

    fields = [
        "name",
        "read_permission",
        "write_permission",
        "delete_permission",
        "user",
    ]
    print(f"<table><tr><td>{'</td><td>'.join(fields)}</td></tr>")

    try:
        files = {
            file.name: {field: getattr(file, field) for field in fields}
            for file in get_files()
        }
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
        sys.exit(127)

    for file in files.values():
        print(
            f"<tr><td>{file['name']}</td>"
            f"<td>{file['read_permission']}</td>"
            f"<td>{file['write_permission']}</td>"
            f"<td>{file['delete_permission']}</td>"
            f"<td>{file['user']}</td></tr>"
        )

    print("</table>")


if __name__ == "__main__":
    main()
    sys.exit(0)
