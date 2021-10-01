#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file uploads a file on a WebScripts Server
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

This file uploads a file on a WebScripts Server."""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file uploads a file on a WebScripts Server"""
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

from modules.uploads_management import write_file, get_user
from argparse import ArgumentParser, Namespace
import sys


def parse_args() -> Namespace:

    """This function parse command line arguments."""

    owner = get_user()
    groupID = max(owner["groups"])

    parser = ArgumentParser()
    parser.add_argument("name", help="The filename of uploaded file.")
    parser.add_argument(
        "--read-permission",
        "-r",
        help="Minimum Group ID to read the file",
        type=int,
        default=groupID,
    )
    parser.add_argument(
        "--write-permission",
        "-w",
        help="Minimum Group ID to write the file",
        type=int,
        default=groupID,
    )
    parser.add_argument(
        "--delete-permission",
        "-d",
        help="Minimum Group ID to delete the file",
        type=int,
        default=groupID,
    )
    parser.add_argument(
        "--hidden",
        "-H",
        help="Hidden file (unlisted in Web Interface)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--binary",
        "-b",
        help="Upload a binary file (ZIP, executable...)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--no-compression",
        "-c",
        help="Do not compress the file.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--is-b64",
        "-i",
        help="Using base64 to upload the file",
        action="store_true",
        default=False,
    )
    return parser.parse_args()


def main() -> None:

    """This function uploads a file on a WebScripts Server."""

    arguments = parse_args()

    try:
        upload = write_file(sys.stdin.read(), *arguments.__dict__.values())
    except Exception as e:
        print(f"{e.__class__.__name__}: {e}")
        sys.exit(127)

    print(
        f"UPLOADED FILE:\n\t - Name: {upload.name}"
        f"\n\t - Permissions: r={upload.read_permission};"
        f"w={upload.write_permission};d={upload.delete_permission};"
        f"\n\t - {upload.hidden}"
    )


if __name__ == "__main__":
    main()
    sys.exit(0)
