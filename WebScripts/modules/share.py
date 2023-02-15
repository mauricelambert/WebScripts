#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool runs CLI scripts and displays output in a Web Interface.
#    Copyright (C) 2021, 2022, 2023  Maurice Lambert

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
This tool runs CLI scripts and displays output in a Web Interface.

This file download and upload functions for scripts,
tools and command line client.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file download and upload functions for scripts,
tools and command line client.
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = ["Download", "upload"]

from typing import List, Tuple, Dict, TypeVar, Union, Iterable
from os import path, _Environ, environ as env
from sys import path as syspath, modules
from tempfile import TemporaryFile
from lzma import open as lzmaopen
from gzip import open as gzipopen
from types import MethodType
from json import dumps

# if "WebScripts" in sys.modules:
#     base_path = [path.dirname(sys.modules["WebScripts"].__file__)]
# elif "WebScripts38" in sys.modules:
#     base_path = [path.dirname(sys.modules["WebScripts38"].__file__)]
# else:
#     base_path = [path.dirname(__file__), ".."]

syspath.insert(
    0,
    path.join(env.get("WEBSCRIPTS_PATH", ""), "scripts", "uploads", "modules"),
)

from uploads_management import (
    User,
    write_file,
    check_permissions,
    get_real_file_name,
    get_file,
    get_files,
    Upload,
)

syspath.pop(0)
Server = TypeVar("Server")

module_getter: MethodType = modules.get
check_right = module_getter(
    "WebScripts.Pages"
    if module_getter("WebScripts")
    else "WebScripts38.Pages",
    module_getter("Pages"),
).check_right


class Download:

    """
    This class implement download functions for filename or ID.
    """

    def filename(
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[Iterable[bytes], bytes]]:
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

        return (
            "200 OK",
            headers,
            Download.get_data(file),
        )

    @staticmethod
    def get_data(file: Upload) -> Iterable[bytes]:
        """
        This function get file and manage the compression.
        """

        file_ = open(
            get_real_file_name(file.name, float(file.timestamp)), "rb"
        )

        if file.is_binary == "binary" and not file.no_compression:
            tempfile = TemporaryFile()
            gzipfile = gzipopen(tempfile, "wb")
            writer = gzipfile.write
            [writer(line) for line in lzmaopen(file_)]
            tempfile.seek(0)
            gzipfile = gzipopen(tempfile)
            data = gzipfile
        else:
            data = file_

        return data

    def id(
        environ: _Environ,
        user: User,
        server: Server,
        id_: str,
        arguments: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[Iterable[bytes], bytes]]:
        """
        This funtion download file by ID.
        """

        script = server.pages.scripts.get("get_any_file.py")
        permissions = getattr(server.configuration, "admin_groups", None)

        if script and not check_right(user, script):
            return "403", {}, b""
        elif permissions and not any(g in permissions for g in user["groups"]):
            return "403", {}, b""

        headers = {
            "Content-Type": "application/octet-stream",
        }

        ask_file = None

        for file in get_files():
            if file.ID == id_:
                ask_file = file
                break

        if ask_file is None:
            return "404", {}, b""

        if not ask_file.no_compression:
            headers["Content-Encoding"] = "gzip"

        return (
            "200 OK",
            headers,
            Download.get_data(ask_file),
        )


def upload(
    environ: _Environ,
    user: User,
    server: Server,
    filename: str,
    data: bytes,
    none: None,
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:
    """
    This funtion upload file.
    """

    if not isinstance(data, bytes):
        data = dumps(data)
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

    env["USER"] = dumps(user.get_dict())

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
