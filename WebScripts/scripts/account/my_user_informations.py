#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file adds a new user.
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

This file adds a new user.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file adds a new user.
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

__all__ = ["main"]

from modules.manage_defaults_databases import get_dict_groups
from os import environ
from json import loads
from sys import exit


def main() -> int:

    """
    This function prints user configurations.
    """

    groups = get_dict_groups()
    user = loads(environ["USER"])

    print(
        f"""
Username: {user['name']!r}
ID: {user['ID']!r}
Groups (defined permissions): {[f'{groups.get(str(group), "UNKNOWN")!r} ({group})' for group in user['groups']]}
IP adresses (allowed for authentication): {user['IPs']!r}
Categories (defined access): {', '.join(user['categories'])}
Scripts (defined access): {', '.join(user['scripts'])}
		"""
    )

    return 0


if __name__ == "__main__":
    exit(main())
