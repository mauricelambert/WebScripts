#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can change a user password
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

This file can change a user password."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file can change a user password."""
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

from modules.manage_defaults_databases import change_user_password
from argparse import ArgumentParser, Namespace
import sys


def parse_args() -> Namespace:

    """This function parse command line arguments."""

    parser = ArgumentParser()
    parser.add_argument("user_id", help="User ID")
    parser.add_argument("password", help="New password")
    return parser.parse_args()


def main() -> None:

    """Main function to change a user password."""

    arguments = parse_args()

    try:
        user = change_user_password(arguments.user_id, arguments.password)
    except Exception as error:
        print(error)
        sys.exit(127)

    if user is None:
        print(f"User ID: {arguments.user_id} doesn't exist.")
        sys.exit(2)

    print(
        f"Password changed for user:\n\t - Name: {user.name}\n\t - ID: {user.ID}\n\t - IPs: {user.IPs}\n\t - Groups: {user.groups}"
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
