#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can change the password of current user
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

This file can change the password of current user.
"""

__version__ = "0.1.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file can change the password of current user."""
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

from modules.manage_defaults_databases import change_user_password
from argparse import ArgumentParser, Namespace
from sys import stderr, exit
from os import environ
from json import loads


def parse_args() -> Namespace:
    """This function parse command line arguments."""

    parser = ArgumentParser(
        description="This script change your WebScripts password."
    )
    parser_add_argument = parser.add_argument
    parser_add_argument("old_password", help="Your current password")
    parser_add_argument("password", help="New password")
    parser_add_argument(
        "password_confirmation", help="New password configuration"
    )
    return parser.parse_args()


def main() -> int:
    """Main function to change your password."""

    arguments = parse_args()
    user_id = str(loads(environ["USER"])["id"])

    if arguments.password != arguments.password_confirmation:
        print("Password and password confirmation do not match.", file=stderr)
        return 3

    try:
        user = change_user_password(
            user_id, arguments.password, old_password=arguments.old_password
        )
    except Exception as error:
        print(error)
        return 127

    if user is None:
        print(f"User ID: {user_id} doesn't exist.", file=stderr)
        return 2
    elif user is False:
        print("Authentication failed: Old password is not valid.", file=stderr)
        return 3

    print(
        f"Password changed for user:\n\t - Name: {user.name}\n\t - ID:"
        f" {user.ID}\n\t - IPs: {user.IPs}\n\t - Groups: {user.groups}"
    )


if __name__ == "__main__":
    exit(main())
