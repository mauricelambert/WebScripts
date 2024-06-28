#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file prints a JSON object of uploaded files
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

This file prints a JSON object of uploaded files.
"""

__version__ = "1.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file prints a JSON object of uploaded files
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

from modules.uploads_management import get_visible_files
from sys import exit, stderr, stdout
from json import dump


def main() -> int:
    """
    This function prints the JSON object of uploaded files.
    """

    fields = [
        "name",
        "read_permission",
        "write_permission",
        "delete_permission",
        "user",
    ]

    try:
        files = get_visible_files()
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}", file=stderr)
        return 127

    files = {
        key: value
        for file in files.values()
        for key, value in file._asdict().items()
        if key in fields
    }

    dump(files, stdout)

    return 0


if __name__ == "__main__":
    exit(main())
