#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file may display the license and copyright of WebScripts
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

This file may display the license and copyright of WebScripts.
"""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This tool run scripts and display the result in a Web Interface.

This file may display the license and copyright of WebScripts."""
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

__all__ = []

from sys import exit, argv, stderr
from os.path import dirname, join
from os import chdir


def main() -> int:

    """
    Main function to display license and copyright of WebScripts.
    """

    chdir(join(dirname(__file__), "..", ".."))

    if len(argv) < 2:
        print(
            "USAGE: show_license.py [part required string]",
            file=stderr,
        )
        return 1

    remove = argv.remove

    if "copyright" in argv:
        remove("copyright")
        print(copyright)

    if "license" in argv:
        remove("license")
        with open("LICENSE.txt") as license:
            print(license.read())

    if "codeheader" in argv:
        remove("codeheader")
        print(
            """    Copyright (C) 2021, 2022  Maurice Lambert

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
            """
        )

    if len(argv) > 1:
        print(
            f"ERROR: unexpected arguments {argv[1:]}",
            file=stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    exit(main())
