#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can add a group
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

"""This tool run scripts and display the result in a Web Interface.

This file can add a group."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file can add a group."""
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

from modules.manage_defaults_databases import add_group, GroupError
import sys


def main() -> None:
    if len(sys.argv) != 3 and not sys.argv[2].isdigit():
        print(
            "USAGE: add_group.py [NAME string required] [ID integer required]"
        )
        sys.exit(1)

    try:
        group = add_group(sys.argv[2], sys.argv[1])
    except GroupError as error:
        print(error)
        sys.exit(2)
    except Exception as error:
        print(error)
        sys.exit(127)

    print(f"Group added:\n\t - Name: {group.name}\n\t - ID: {group.ID}")


if __name__ == "__main__":
    main()
    sys.exit(0)
