#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can authenticate user
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

This file can authenticate user."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file can authenticate user"""
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

from modules.manage_defaults_databases import auth
from argparse import ArgumentParser, Namespace
from os import environ
import json
import sys


def parse_args() -> Namespace:

    """This function parse command line arguments."""

    parser = ArgumentParser()
    parser.add_argument(
        "--username", "-u", help="Username to authenticate the user."
    )
    parser.add_argument(
        "--password", "-p", help="Password to authenticate the user."
    )
    parser.add_argument(
        "--api-key", "-a", help="API key to authenticate the user."
    )
    return parser.parse_args()


def main() -> None:

    """Main function to authenticate the user."""

    parser = parse_args()

    if (
        parser.username is None or parser.password is None
    ) and parser.api_key is None:
        print(
            "USAGES:\n\t - auth.py --username [USERNAME string required]"
            " --password [PASSWORD string required]\n\t - auth.py --api-key"
            " [APIKEY string required]"
        )
        sys.exit(1)

    if parser.api_key is not None:
        arguments = {"apikey": parser.api_key}
    else:
        arguments = {"username": parser.username, "password": parser.password}

    try:
        user = auth(**arguments)
    except Exception as error:
        print(error)
        sys.exit(127)

    if user is None:
        print("Authentication failed.")
        sys.exit(3)

    print(
        json.dumps(
            {
                "id": user.ID,
                "name": user.name,
                "ip": environ.get("X_REAL_IP")
                or environ.get("X_FORWARDED_FOR")
                or environ.get("X_FORWARDED_HOST")
                or environ["REMOTE_ADDR"],
                "groups": user.groups,
                "categories": user.categories,
                "scripts": user.scripts,
            }
        )
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
