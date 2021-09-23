#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file change the code for python3.8 compatibility
#    from the command line and display the result in a web interface.
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

This file change the code for python3.8 compatibility.

To install WebScripts with python3.8 compatibility 
as package run the following commands line:
    - python3.8 to_3.8.py
    - python3.8 ../../../setup38.py install

The new package is named WebScripts38.

Impact: "log_encoding" configuration is not use.
"""

__version__ = "0.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file change the code for python3.8 compatibility."""
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

from shutil import copytree, copyfile
from os import path
import logging
import glob
import sys
import re

def copy(directory: str, setup_filename: str) -> None:

    """This function copy the WebScripts directory and the setup."""

    logging.warning("Copy the WebScripts directory and the setup filename...")
    copytree(path.join(directory, "WebScripts"), path.join(directory, "WebScripts38"))
    copyfile(path.join(directory, "setup.py"), setup_filename)
    logging.info("Copy the WebScripts directory and the setup filename...")

def change_setup(filename: str) -> None:

    """This function change the setup.py file."""

    content = open(filename).read()
    logging.warning("Change the new setup content...")

    with open(filename, "w") as file:
        file.write(content.replace(
            "import WebScripts as package",
            "import WebScripts38 as package"
        ).replace(
            'python_requires=">=3.9",',
            'python_requires=">=3.8",'
        ))

    logging.info("New setup is changed.")

def change_manifest(filename: str) -> None:

    """This function change the manifest.in file."""

    content = open(filename).read()
    logging.warning("Change the new manifest content...")

    with open(filename, "w") as file:
        file.write(content.replace(
            "WebScripts/",
            "WebScripts38/"
        ))

    logging.info("New manifest is changed.")

def change_utils(filename: str):

    """This function change the utils.py file."""

    logging.warning("Change the new utils.py content...")
    content = open(filename).read()

    with open(filename, "w") as file:
        file.write(content.replace(
            "from typing import TypeVar, List, Dict, _SpecialGenericAlias, _GenericAlias",
            "from typing import TypeVar, List, Dict, _GenericAlias"
        ).replace(
            """ or isinstance(
                type_, _SpecialGenericAlias
            )""", ""
        ))

    logging.info("New utils.py is changed.")

def change_WebScripts(filename: str):

    """This function change the WebScripts.py file."""

    logging.warning("Change the new WebScripts.py content...")
    content = open(filename).read()

    with open(filename, "w") as file:
        file.write(content.replace(
            'encoding="utf-8",',
            ""
        ).replace(
            '"log_encoding": "encoding",',
            ''
        ))

    logging.info("New WebScripts.py is changed.")

def change_subscriptable_iterator(directory: str) -> None:

    """This function change subscriptable Iterators."""

    regex = re.compile(r"Iterator\[\w+\]")
    for filename in glob.glob(path.join(directory, 'WebScripts38', '**', '*.py'), recursive=True):
        content = open(filename).read()
        logging.warning(f"Change the new {filename} content...")

        new_content, number = regex.subn("Iterator", content)

        with open(filename, "w") as file:
            file.write(new_content)
        
        logging.info(f"New {filename} is changed ({number} times).")

def main():

    """This function execute the file."""

    logging.debug("Set the WebScripts directory and the setup filename...")
    webscript_dir = path.join(path.dirname(__file__), "..", "..", "..")
    new_setup = path.join(webscript_dir, "setup38.py")

    copy(webscript_dir, new_setup)
    change_manifest(path.join(webscript_dir, "MANIFEST.in"))
    change_setup(new_setup)
    change_utils(path.join(webscript_dir, "WebScripts38", "utils.py"))
    change_WebScripts(path.join(webscript_dir, "WebScripts38", "WebScripts.py"))
    change_subscriptable_iterator(webscript_dir)

if __name__ == "__main__":
    logging.basicConfig(level=0)
    main()
    sys.exit(0)
