#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file write HTML documentation using pydoc
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

This file write HTML documentation using pydoc."""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file write HTML documentation using pydoc."""
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

from pydoc import resolve, html, describe, ErrorDuringImport
from os import path
import sys


def main() -> None:

    """This file write HTML documentation using pydoc."""

    if len(sys.argv) != 2:
        print("USAGE: py_doc.py [filename string required]")
        sys.exit(1)

    COLORS = {
        "#ffc8d8": "#EEC477",  # pink
        # "#ee77aa": "#A57927",
        "#ee77aa": "#C89B48",  # pink
        "#aa55cc": "#75B4AD",  # purple
        "#7799ee": "#9286C2",  # blue
        "#55aa55": "#18675F",  # green
        "#eeaa77": "#A57927",  # orange
    }

    filename = sys.argv[1]
    dirname, name = path.split(path.abspath(filename))

    sys.path.append(dirname)
    name_only, extension = path.splitext(name)

    try:
        object, name = resolve(name_only)
        page = html.page(describe(object), html.document(object, name))

        for old_color, new_color in COLORS.items():
            page = page.replace(
                f'bgcolor="{old_color}"', f'bgcolor="{new_color}"'
            )

        filename = path.join(path.dirname(__file__), "..", "..", "doc", name)

        with open(f"{filename}.html", "w", encoding="utf-8") as file:
            file.write(page)

    except (ImportError, ErrorDuringImport) as value:
        print(value)

    del sys.path[-1]


if __name__ == "__main__":
    main()
    sys.exit(0)
