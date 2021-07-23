#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file can print the API key of the current user
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

This file can print the API key of the current user."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file can print the API key of the current user."""
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

from modules.manage_defaults_databases import get_apikey
from os import environ
import json
import sys


def main() -> None:

    """Main function to print the API key of the current user."""

    if len(sys.argv) != 2:
        print("USAGE: get_apikey.py [password string required]")
        sys.exit(1)

    user_id = str(json.loads(environ["USER"])["id"])
    apikey = get_apikey(user_id, sys.argv[1])

    if apikey is None:
        print("Authentication failed")
        sys.exit(2)

    print(apikey)


if __name__ == "__main__":
    main()
    sys.exit(0)
