#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implement some functions to manage requests/reports on WebScripts
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

This file implement some functions to manage requests/reports on WebScripts."""

__version__ = "0.1.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file implement some functions to manage requests/reports on WebScripts"""
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

__all__ = [
    "Request",
    "get_requests",
    "get_request",
    "delete_request",
]

from time import time, strftime, localtime
from base64 import b64encode, b64decode
from typing import Tuple, List, TypeVar
from os import environ, path, replace
from collections.abc import Iterator
from collections import namedtuple
from html import escape
import json
import csv

Request = namedtuple(
    "Request",
    [
        "ID",
        "Time",
        "UserName",
        "ErrorCode",
        "Page",
        "UserAgent",
        "Subject",
        "Reason",
        "Name",
    ],
)
FILE = "requests.csv"
DIRECTORY = path.join(
    path.dirname(__file__),
    "..",
    "..",
    "..",
    "data",
)


def anti_XSS(named_tuple: namedtuple) -> namedtuple:

    """This function returns a namedtuple without HTML special characters."""

    new = {}
    for attribut, value in named_tuple._asdict().items():
        new[attribut] = escape(value)
    return named_tuple.__class__(**new)


def get_requests() -> Iterator[Request]:

    """This function build Uploads from database."""

    yield from map(
        Request._make,
        csv.reader(
            open(path.join(DIRECTORY, FILE), "r", newline=""), quoting=csv.QUOTE_ALL
        ),
    )


def get_request(id_: str) -> Request:

    """This function return a specific request."""

    for request in get_requests():
        if request.ID == id_:
            return anti_XSS(request)

    raise ValueError("This request ID doesn't exists.")


def delete_request(id_: str) -> Request:

    """This function rewrite the request database without the specified request."""

    deleted_request = None
    filename = path.join(DIRECTORY, f"{FILE}.new")

    with open(filename, "w", newline="") as file:
        csvwriter = csv.writer(file, quoting=csv.QUOTE_ALL)

        for request in get_requests():
            if request.ID == id_:
                deleted_request = request
            else:
                csvwriter.writerow(anti_XSS(request))

    if deleted_request is None:
        raise ValueError("This request ID doesn't exists.")

    replace(filename, path.join(DIRECTORY, FILE))
    return anti_XSS(deleted_request)
