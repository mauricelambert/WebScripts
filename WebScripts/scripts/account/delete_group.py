#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can delete group and print the deleted group
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

"""This tools run scripts and display the result in a Web Interface.

This file can delete group and print the deleted group."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file can delete group and print the deleted group."""
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

from modules.manage_defaults_databases import delete_group
import sys


def main() -> None:
    if len(sys.argv) != 2 and sys.argv[1].isdigit():
        try:
            group = delete_group(int(sys.argv[1]))
        except Exception as error:
            print(error)
            sys.exit(127)

        if group is None:
            print(f"Group ID: {sys.argv[1]} doesn't exist.")
            sys.exit(2)

        print(f"Deleted group:\n\t - Name: {group.name}\n\t - ID: {group.ID}")
    else:
        print("USAGE: delete_group.py [ID integer required]")
        sys.exit(1)


if __name__ == "__main__":
    main()
    sys.exit(0)
