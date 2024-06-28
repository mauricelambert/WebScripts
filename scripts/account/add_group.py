#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file adds a new group
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

This file adds a new group.
"""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file adds a new group.
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

from modules.manage_defaults_databases import add_group, GroupError
from sys import exit, argv, stderr


def main() -> int:
    if len(argv) != 3 and not argv[2].isdigit():
        print(
            "USAGES: add_group.py [NAME string required] [ID integer required]"
        )
        return 1

    try:
        group = add_group(argv[2], argv[1])
    except GroupError as error:
        print(error.__class__.__name__, error, file=stderr)
        return 2
    except Exception as error:
        print(error.__class__.__name__, error, file=stderr)
        return 127

    print(f"Group added:\n\t - Name: {group.name}\n\t - ID: {group.ID}")

    return 0


if __name__ == "__main__":
    exit(main())
