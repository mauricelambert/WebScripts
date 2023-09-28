#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file adds a new user.
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

This file adds a new user.
"""

__version__ = "1.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file adds a new user.
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

__all__ = ["parse_args", "main"]

from modules.manage_defaults_databases import (
    add_user,
    UserError,
    get_dict_groups,
)
from argparse import ArgumentParser, Namespace
from sys import exit, stderr


def parse_args() -> Namespace:
    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(description="This file adds a new user.")
    add_argument = parser.add_argument

    add_argument("username", help="Name of the new user")
    add_argument("password", help="Password of the new user")
    add_argument(
        "--groups",
        "-g",
        help="List of groups IDs to add permissions to the new user.",
        type=int,
        nargs="+",
        default=[],
    )
    add_argument(
        "--group-names",
        "-n",
        help="List of groups names to add permissions to the new user.",
        nargs="+",
        default=[],
    )
    add_argument(
        "--ips",
        "-i",
        help="List of glob syntax for authorized IPs",
        type=str,
        nargs="+",
        default=["*"],
    )
    add_argument(
        "--categories",
        "-c",
        help="List of glob syntax for authorized categories",
        type=str,
        nargs="+",
        default=["*"],
    )
    add_argument(
        "--scripts",
        "-s",
        help="List of glob syntax for authorized scripts",
        type=str,
        nargs="+",
        default=["*"],
    )
    return parser.parse_args()


def main() -> int:
    """
    This function adds a new user using the
    default user manager.
    """

    arguments = parse_args()

    groups = get_dict_groups(by_name=True)

    user_namedgroups = [
        groups[name] for name in arguments.group_names if name in groups
    ]

    groups = arguments.groups + user_namedgroups
    if not groups:
        print(
            "A group is required you must use [--groups/-g] or/and "
            "[--group-names/-n] option.",
            file=stderr,
        )
        return 3

    try:
        user = add_user(
            arguments.username,
            arguments.password,
            groups,
            arguments.ips,
            arguments.categories,
            arguments.scripts,
        )
    except UserError as error:
        print(error, file=stderr)
        return 2
    except Exception as error:
        print(error, file=stderr)
        return 127

    groups = get_dict_groups()

    print(
        f"User added:\n\t - Name: {user.name!r}\n\t - ID: {user.ID}\n\t - IPs:"
        f" {user.IPs}\n\t - Groups: "
        + ",".join(
            f'{groups.get(group, "UNKNOWN")!r} ({group})'
            for group in user.groups.split(",")
        )
    )

    return 0


if __name__ == "__main__":
    exit(main())
