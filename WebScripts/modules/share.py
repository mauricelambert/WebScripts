#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tools run scripts and display the result in a Web Interface.
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

This file download and upload functions for scripts,
tools and command line client."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file download and upload functions for scripts,
tools and command line client."""
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

from typing import List, Tuple, Dict, TypeVar
from os import path, _Environ
from lzma import decompress
from gzip import compress
import json
import sys
import os

sys.path = [
    path.join(path.dirname(__file__), "..", "scripts", "uploads", "modules"),
] + sys.path

from uploads_management import (
    User,
    write_file,
    check_permissions,
    get_real_file_name,
    get_file,
)

ServerConfiguration = TypeVar("ServerConfiguration")


class Download:

    """
    This class implement download functions for filename or ID.
    """

    def filename(
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This funtion download file by filename.
        """

        uploads, counter = get_file(filename)

        if len(uploads) == 0:
            return "404", {}, b""

        file = uploads[-1]

        try:
            check_permissions(file, user.get_dict(), "read")
        except PermissionError:
            return "403", {}, b""
        except FileNotFoundError:
            return "404", {}, b""

        headers = {
            "Content-Type": "application/octet-stream",
        }

        if not file.no_compression:
            headers["Content-Encoding"] = "gzip"

        with open(
            get_real_file_name(file.name, float(file.timestamp)), "rb"
        ) as file_:

            if file.is_binary == "binary" and not file.no_compression:
                data = compress(decompress(file_.read()))
            else:
                data = file_.read()

            return (
                "200 OK",
                headers,
                data,
            )

    def id(
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This funtion download file by ID.
        """

        raise NotImplementedError(
            "This function is not yet implemented for permission reasons."
        )


def upload(
    environ: _Environ,
    user: User,
    server_configuration: ServerConfiguration,
    filename: str,
    data: bytes,
    none: None,
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:

    """
    This funtion upload file.
    """

    if not isinstance(data, bytes):
        data = json.dumps(data)
    else:
        data = data.decode("latin-1")

    permissions = max(user.groups)

    read = int(environ.get("HTTP_READ_PERMISSION", permissions))
    write = int(environ.get("HTTP_WRITE_PERMISSION", permissions))
    delete = int(environ.get("HTTP_DELETE_PERMISSION", permissions))

    hidden = environ.get("HTTP_HIDDEN", False)
    binary = environ.get("HTTP_BINARY", False)
    no_compression = environ.get("HTTP_NO_COMPRESSION", False)
    is_b64 = environ.get("HTTP_IS_BASE64", False)

    os.environ["USER"] = json.dumps(user.get_dict())

    write_file(
        data,
        filename,
        read,
        write,
        delete,
        hidden,
        binary,
        no_compression,
        is_b64,
    )

    return (
        "200 OK",
        {"Content-Type": "text/plain"},
        "OK: file is uploaded.",
    )
