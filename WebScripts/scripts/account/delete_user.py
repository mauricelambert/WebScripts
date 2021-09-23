#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can delete user and print the deleted user
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

This file can delete user and print the deleted user."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file can delete user and print the deleted user."""
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

from modules.manage_defaults_databases import delete_user
import sys


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1].isdigit():
        user = delete_user(int(sys.argv[1]))

        if user is None:
            print(f"User ID: {sys.argv[1]} doesn't exist.")
            sys.exit(2)

        print(
            f"Deleted user:\n\t - Name: {user.name}\n\t - ID: {user.ID}\n\t - IPs: {user.IPs}\n\t - Groups: {user.groups}"
        )
    else:
        print("USAGE: delete_user.py [ID integer required]")
        sys.exit(1)


if __name__ == "__main__":
    main()
    sys.exit(0)
