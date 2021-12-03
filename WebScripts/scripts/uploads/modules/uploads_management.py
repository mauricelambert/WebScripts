#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implement some functions to manage uploads on WebScripts
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

This file implement some functions to manage uploads on WebScripts."""

__version__ = "0.0.6"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tools run scripts and display the result in a Web Interface.

This file implement some functions to manage uploads on WebScripts"""
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
    "Upload",
    "get_file",
    "read_file",
    "write_file",
    "delete_file",
    "get_file_content",
    "get_visible_files",
]

from gzip import compress as gzip, decompress as ungzip
from lzma import compress as xz, decompress as unxz
from collections import namedtuple, Counter
from time import time, strftime, localtime
from typing import Tuple, List, TypeVar
from base64 import b64encode, b64decode
from collections.abc import Iterator
from os import environ, path
from html import escape
from math import ceil
import json
import csv

Upload = namedtuple(
    "Upload",
    [
        "ID",
        "name",
        "read_permission",
        "write_permission",
        "delete_permission",
        "hidden",
        "is_deleted",
        "is_binary",
        "no_compression",
        "timestamp",
        "user",
        "version",
    ],
)
FILE = "uploads.csv"
DIRECTORY = path.join(
    path.dirname(__file__),
    "..",
    "..",
    "..",
    "data",
)
FILES_DIRECTORY = "uploads"
User = TypeVar("User")
Data = TypeVar("Data", str, bytes)


def upgrade_uploads() -> None:

    """This function upgrade the database.

    Add default no_compression ("", empty string)
    """

    uploads = []
    first = False

    with open(path.join(DIRECTORY, FILE), newline="") as csvfile:
        csvreader = csv.reader(csvfile, quoting=csv.QUOTE_ALL)

        for row in csvreader:
            if len(row) == 11:

                if first:
                    row.insert(8, "")
                else:
                    row.insert(8, "no_compression")
                    first = True

            uploads.append(row)

    with open(path.join(DIRECTORY, FILE), "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile, quoting=csv.QUOTE_ALL)

        for upload in uploads:
            csvwriter.writerow(upload)


def anti_XSS(named_tuple: namedtuple) -> namedtuple:

    """This function returns a namedtuple without HTML special characters."""

    new = {}
    for attribut, value in named_tuple._asdict().items():
        new[attribut] = escape(value)
    return named_tuple.__class__(**new)


def get_files() -> Iterator[Upload]:

    """This function build Uploads from database."""

    yield from map(
        Upload._make,
        csv.reader(
            open(path.join(DIRECTORY, FILE), "r", newline=""),
            quoting=csv.QUOTE_ALL,
        ),
    )


def get_visible_files() -> Iterator[Upload]:

    """This function return upload if not hidden."""

    files = {}

    for file in get_files():
        file = anti_XSS(file)
        if file.hidden != "hidden" and file.is_deleted != "deleted":
            files[file.name] = file
        elif (
            file.hidden == "hidden" or file.is_deleted == "deleted"
        ) and file.name in files.keys():
            del files[file.name]

    return files


def write_file(
    data: str,
    name: str,
    read_access: int,
    write_access: int,
    delete_access: int,
    hidden: bool,
    binary: bool,
    no_compression: bool,
    is_b64: bool,
    with_access: bool = True,
) -> Upload:

    """This function upload a file."""

    owner = get_user()
    uploads, counter = get_file(name)

    if with_access and len(uploads) != 0:
        file = uploads[-1]
        check_permissions(file, owner, "write")

    timestamp = time()

    upload = anti_XSS(
        Upload(
            str(sum(counter.values())),
            name,
            str(read_access),
            str(write_access),
            str(delete_access),
            "hidden" if hidden else "visible",
            "exist",
            "binary" if binary else "text",
            "no_compression" if no_compression else "",
            str(timestamp),
            owner["name"],
            str(counter[name]),
        )
    )

    write_action(upload)

    if is_b64:
        data = b64decode(data.encode())
    else:
        data = data.encode("utf-8")

    filename = get_real_file_name(name, timestamp)

    if not no_compression and not binary:
        data = gzip(data)
    elif not no_compression and binary:
        data = xz(data)

    with open(
        filename,
        "wb",
    ) as file:
        file.write(data)

    return upload


def unicode_to_bytes(string: str) -> bytes:

    """This function return bytes from unicode strings."""

    data = b""
    for char in string:
        char = ord(char)
        data += char.to_bytes(ceil(char.bit_length() / 8), "big")

    return data


def delete_file(name: str) -> Upload:

    """This function delete an uploaded file."""

    uploads, counter = get_file(name)

    if len(uploads) == 0:
        raise FileNotFoundError(f"No such file or directory: {name}.")

    file = uploads[-1]
    owner = get_user()
    check_permissions(file, owner, "delete")
    timestamp = time()

    upload = anti_XSS(
        Upload(
            str(sum(counter.values())),
            file.name,
            file.read_permission,
            file.write_permission,
            file.delete_permission,
            file.hidden,
            "deleted",
            file.is_binary,
            file.no_compression,
            str(timestamp),
            owner["name"],
            file.version,
        )
    )
    write_action(upload)

    return upload


def write_action(upload: Upload) -> None:

    """
    This function write a new line in CSV database.
    """

    for string in upload:
        if not string.isprintable():
            raise ValueError(f"Strings must be printable: '{string}' is not.")

    with open(path.join(DIRECTORY, FILE), "a", newline="") as csvfile:
        csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        csv_writer.writerow(anti_XSS(upload))


def check_permissions(file: Upload, owner: User, attr: str) -> None:

    """This function raises a PermissionError if
    the user does not have write permission."""

    permission = int(getattr(file, f"{attr}_permission"))

    if (
        attr == "write"
        and permission > max(owner["groups"])
        and file.is_deleted != "deleted"
    ):
        raise PermissionError(
            f"To write on this file ({file.name}) a group ID greater"
            f" than {permission} is required."
        )
    elif (attr == "read" or attr == "delete") and permission > max(
        owner["groups"]
    ):
        raise PermissionError(
            f"To {attr} this file ({file.name}) a group ID "
            f"greater than {permission} is required."
        )
    elif (attr == "read" or attr == "delete") and file.is_deleted == "deleted":
        raise FileNotFoundError(f"No such file or directory: {file.name}.")


def get_user() -> User:

    """This function return the user."""

    user = json.loads(environ["USER"])
    return user


def read_file(name: str) -> str:

    """This function check permission and
    return a base64 of the file content."""

    uploads, counter = get_file(name)

    if len(uploads) == 0:
        raise FileNotFoundError(f"No such file or directory: {name}.")

    file = uploads[-1]
    owner = get_user()
    check_permissions(file, owner, "read")

    return get_content(file)


def get_content(file: Upload) -> str:

    """This function read, decompress and encode/decode the file content."""

    with open(
        get_real_file_name(file.name, float(file.timestamp)), "rb"
    ) as file_:
        data = file_.read()

    if not file.no_compression and file.is_binary == "text":
        data = ungzip(data)
    elif not file.no_compression and file.is_binary == "binary":
        data = unxz(data)

    return b64encode(data).decode()


def get_file_content(name: str = None, id_: str = None) -> Tuple[str, str]:

    """This function return a base64 of the file
    content and the filename (without check permissions).

    If id_ and name arguments are None this function return (None, None).

    Using a name this function return the last versions of the file content.
    Using an ID this function return the version of this ID."""

    if id_ is not None:
        error_description = f'using "{id_}" as ID'

    elif name is not None:
        error_description = f'using "{name}" as name'

    else:
        return None, None

    uploads, counter = get_file(name, id_=id_)

    if len(uploads) == 0:
        raise FileNotFoundError(
            f"No such file or directory: {error_description}."
        )

    file = uploads[-1]
    filename = get_real_file_name(file.name, float(file.timestamp))

    if not path.exists(filename):
        raise FileNotFoundError(
            f"No such file or directory: {error_description}."
        )

    only_filename = path.split(file.name)[1]
    return get_content(file), only_filename


def get_file(name: str, id_: str = None) -> Tuple[List[Upload], Counter]:

    """This function return the history of a file.

    If name is None, this function get Upload by ID."""

    versions = []
    counter = Counter()

    for file in get_files():
        file = anti_XSS(file)
        counter[file.name] += 1
        if file.name == name or (name is None and id_ == file.ID):
            versions.append(file)

    return versions, counter


def get_real_file_name(filename: str, timestamp: float) -> str:

    """This function return the real filename of a file."""

    filename, extension = path.splitext(path.split(filename)[1])

    return path.join(
        DIRECTORY,
        FILES_DIRECTORY,
        f"{filename}_"
        f"{strftime('%y%m%d_%H%M%S', localtime(timestamp))}{extension}",
    )


try:
    for upload in get_files():
        break
except TypeError:
    upgrade_uploads()
