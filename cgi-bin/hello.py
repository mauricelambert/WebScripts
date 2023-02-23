#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool run scripts and display the result in a Web Interface.
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

This file implements a CGI script for example (parse arguments and body).
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file implements a CGI script for example (parse arguments and body).
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

__all__ = ["parse_args"]

from cgi import FieldStorage, parse, MiniFieldStorage
from urllib.parse import unquote, parse_qs

# from cgitb import enable
from os import environ
from sys import argv

# enable() # debug mode


def parse_args(*args, **kwargs) -> None:

    """
    This function parses arguments/body with
    differents functions/tools.
    """

    print("\t\t - Simple parsing:")
    if len(argv) == 2:
        arguments = unquote(argv[1])
        print(f"\t\t\t - Arguments: {argv[0]!r} {argv[1]!r}")
    else:
        arguments = parse_qs(
            environ["QUERY_STRING"], *args, **kwargs
        ) or parse(*args, **kwargs)
        for key, values in arguments.items():
            print(
                "\t\t\t - ",
                repr(key),
                "=",
                *[(repr(v) + ", ") for v in values],
            )

    print("\t\t - Complex parsing:")
    arguments = FieldStorage(*args, **kwargs)
    for argument_name in arguments.keys():
        value = arguments[argument_name]
        if isinstance(value, MiniFieldStorage):
            print(
                "\t\t\t - ",
                repr(argument_name),
                "=",
                repr(value.value) + ",",
                value,
            )
        elif isinstance(value, list):
            print(
                "\t\t\t - ",
                repr(argument_name),
                "=",
                [(repr(v.value) + ",") for v in value],
                *value,
            )


print("Content-Type: text/plain")
print()
print("Hello world !")

print("\t 1. Don't keep blank values: ")
parse_args()
print("\t 2. Keep blank values: ")
parse_args(keep_blank_values=True)

print("- WebScripts -")
