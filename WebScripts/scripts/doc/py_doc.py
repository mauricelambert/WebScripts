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

"""This package implements a web server to run scripts or 
executables from the command line and display the result 
in a web interface.

This file write HTML documentation using pydoc."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

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
from os import path, getcwd, chdir
import sys

# chdir(path.join(path.dirname(__file__), "..", ".."))


def main() -> None:

    """This file write HTML documentation using pydoc."""

    if len(sys.argv) != 2:
        print(
            "USAGE: py_doc.py [filename string required]"
        )
        sys.exit(1)

    COLORS = {
        "#ffc8d8": "#EEC477",
#        "#ee77aa": "#A57927",
        "#ee77aa": "#C89B48",
        "#aa55cc": "#4A948C",
    }

    filename = sys.argv[1]
    dirname, name = path.split(path.abspath(filename))

    sys.path.append(dirname)
    name_only, extension = path.splitext(name)

    try:
        object, name = resolve(name_only)
        page = html.page(describe(object), html.document(object, name))

        for old_color, new_color in COLORS.items():
            page = page.replace(f'bgcolor="{old_color}"', f'bgcolor="{new_color}"')

        # filename = path.join(getcwd(), "documentation", name)
        filename = path.join(getcwd(), "doc", name)

        with open(f"{filename}.html", "w", encoding="utf-8") as file:
            file.write(page)

    except (ImportError, ErrorDuringImport) as value:
        print(value)

    del sys.path[-1]


if __name__ == "__main__":
    main()
    sys.exit(0)


# ffc8d8: Light pink -> Pale yellow: #EEC477
# ee77aa: Dark pink  -> Dark yellow: #A57927
