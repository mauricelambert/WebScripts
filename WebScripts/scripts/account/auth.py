#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file authenticates users
#    Copyright (C) 2021, 2022  Maurice Lambert

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
This tool run scripts and display the result in a Web Interface.

This file authenticates users
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file authenticates users
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = ["parse_args", "main"]

from modules.manage_defaults_databases import auth
from argparse import ArgumentParser, Namespace
from sys import stderr, exit
from os import environ
from json import dumps


def parse_args() -> Namespace:

    """
    This function parses command line arguments.
    """

    parser = ArgumentParser("This script authenticates users.")
    add_argument = parser.add_argument
    add_argument("--username", "-u", help="Username to authenticate the user.")
    add_argument("--password", "-p", help="Password to authenticate the user.")
    add_argument("--api-key", "-a", help="API key to authenticate the user.")
    return parser.parse_args()


def main() -> None:

    """
    This function authenticates a user.
    """

    arguments = parse_args()

    if (
        arguments.username is None or arguments.password is None
    ) and arguments.api_key is None:
        print(
            "USAGES:\n\t - auth.py --username [USERNAME string required]"
            " --password [PASSWORD string required]\n\t - auth.py --api-key"
            " [APIKEY string required]",
            file=stderr,
        )
        return 1

    try:
        user = auth(**arguments.__dict__)
    except Exception as error:
        print(error, file=stderr)
        return 127

    if user is None:
        print("Authentication failed.")
        return 3

    print(
        dumps(
            {
                "id": user.ID,
                "name": user.name,
                "ip": environ["REMOTE_IP"],
                "groups": user.groups,
                "categories": user.categories,
                "scripts": user.scripts,
            }
        )
    )


if __name__ == "__main__":
    exit(main())
