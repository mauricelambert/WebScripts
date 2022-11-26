#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implement some functions to manage uploads on WebScripts
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

This file implement some functions to manage uploads on WebScripts.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file implement some functions to manage uploads on WebScripts
"""
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
    "get_reader",
    "delete_file",
    "get_metadata",
    "FileMetadata",
    "UploadedFile",
    "get_file_content",
    "get_visible_files",
]

from gzip import open as gzip, decompress as ungzip
from lzma import open as xz, decompress as unxz
from os.path import join, split, splitext, exists
from typing import Tuple, List, TypeVar, Dict
from collections import namedtuple, Counter
from time import time, strftime, localtime
from csv import reader, writer, QUOTE_ALL
from os import environ, stat, stat_result
from base64 import b64encode, b64decode
from collections.abc import Iterator
from collections import defaultdict
from _io import _TextIOBase
from html import escape
from json import loads
from math import ceil

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
DIRECTORY = environ["WEBSCRIPTS_DATA_PATH"]
FILES_DIRECTORY = "uploads"
User = TypeVar("User")
Data = TypeVar("Data", str, bytes)


class FileMetadata:

    """
    This class implements file metadata for
    uploaded files.
    """

    def __init__(self):
        self.full_size = 0
        self.version = 0

    def add(self, stat: stat_result, timestamp: float):

        """
        This function add a version to file metadata.
        """

        size = stat.st_size
        self.version += 1
        self.last_size = size
        self.full_size = size

        self.webscripts_creation = timestamp

        self.modification = stat.st_mtime
        self.creation = stat.st_ctime
        self.access = stat.st_atime


class UploadedFile:

    """
    This class implements the file type for
    uploaded files.
    """

    def __init__(
        self,
        name: str,
        read_access: int,
        write_access: int,
        delete_access: int,
        hidden: bool,
        binary: bool,
        no_compression: bool,
        with_access: bool = True,
    ):

        owner = get_user()
        uploads, counter = get_file(name)

        if with_access and len(uploads) != 0:
            file = uploads[-1]
            check_permissions(file, owner, "write")

        timestamp = time()

        upload = self.upload = anti_XSS(
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

        filename = get_real_file_name(name, timestamp)

        compression = not no_compression
        if compression and not binary:
            self.file = gzip(filename, "wb")
        elif compression and binary:
            self.file = xz(filename, "wb")
        else:
            self.file = open(filename, "wb")

    def __getattr__(self, attr: str):
        if attr in dir(self):
            return object.__getattr__(self, attr)
        return getattr(self.file, attr)

    def __del__(self, *args, **kwargs):
        return self.file.__del__(*args, **kwargs)

    def __enter__(self, *args, **kwargs):
        return self.file.__enter__(*args, **kwargs)

    def __exit__(self, *args, **kwargs):
        return self.file.__exit__(*args, **kwargs)

    def __iter__(self, *args, **kwargs):
        yield from self.file.__iter__(*args, **kwargs)

    def __next__(self, *args, **kwargs):
        yield from self.file.__next__(*args, **kwargs)


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

    """
    This function uploads a file.
    """

    if is_b64:
        data = b64decode(data.encode())
    else:
        data = data.encode("utf-8")

    file = UploadedFile(
        name,
        read_access,
        write_access,
        delete_access,
        hidden,
        binary,
        no_compression,
        with_access,
    )
    file.write(data)
    file.close()

    return file.upload


def upgrade_uploads() -> None:

    """
    This function upgrade the database.

    Add default no_compression ("", empty string)
    """

    uploads = []
    first = False
    filepath = join(DIRECTORY, FILE)
    uploads_add = uploads.append

    with open(filepath, newline="") as csvfile:
        csvreader = reader(csvfile, quoting=QUOTE_ALL)

        for row in csvreader:
            if len(row) == 11:

                if first:
                    row.insert(8, "")
                else:
                    row.insert(8, "no_compression")
                    first = True

            uploads_add(row)

    with open(filepath, "w", newline="") as csvfile:
        csvwriter = writer(csvfile, quoting=QUOTE_ALL)
        writerow = csvwriter.writerow

        [writerow(upload) for upload in uploads]


def anti_XSS(named_tuple: namedtuple) -> namedtuple:

    """
    This function returns a namedtuple
    without HTML special characters.
    """

    new = {}
    for attribut, value in named_tuple._asdict().items():
        new[attribut] = escape(value)
    return named_tuple.__class__(**new)


def get_files() -> Iterator[Upload]:

    """
    This function build Uploads from database.
    """

    yield from map(
        Upload._make,
        reader(
            open(join(DIRECTORY, FILE), "r", newline=""),
            quoting=QUOTE_ALL,
        ),
    )


def get_metadata() -> Dict[str, FileMetadata]:

    """
    This function returns metadata of
    each uploaded files and versions.
    """

    files = defaultdict(FileMetadata)

    for file in get_files():
        name = file.name
        timestamp = float(file.timestamp)
        filename = get_real_file_name(name, timestamp)
        files[name].add(stat(filename), timestamp)

    return files


def get_visible_files() -> Iterator[Upload]:

    """
    This function return upload if not hidden.
    """

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


def unicode_to_bytes(string: str) -> bytes:

    """
    This function return bytes from unicode strings."""

    data = b""
    for char in string:
        char = ord(char)
        data += char.to_bytes(ceil(char.bit_length() / 8), "big")

    return data


def delete_file(name: str) -> Upload:

    """
    This function delete an uploaded file.
    """

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

    with open(join(DIRECTORY, FILE), "a", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        csv_writer.writerow(anti_XSS(upload))


def check_permissions(file: Upload, owner: User, attr: str) -> None:

    """
    This function raises a PermissionError if
    the user does not have write permission.
    """

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

    """
    This function return the user.
    """

    return loads(environ["USER"])


def read_file(name: str) -> str:

    """
    This function check permission and
    return a base64 of the file content.
    """

    uploads, counter = get_file(name)

    if len(uploads) == 0:
        raise FileNotFoundError(f"No such file or directory: {name}.")

    file = uploads[-1]
    owner = get_user()
    check_permissions(file, owner, "read")

    return get_content(file)


def get_reader(file: Upload) -> _TextIOBase:

    """
    This function returns a reader
    of the uploaded file.
    """

    compression = not file.no_compression
    filename = get_real_file_name(file.name, float(file.timestamp))

    if compression and file.is_binary == "text":
        reader = ungzip(filename)
    elif compression and file.is_binary == "binary":
        reader = unxz(filename)
    else:
        reader = open(filename, "rb")

    return reader


def get_content(file: Upload) -> str:

    """
    This function read, decompress and
    encode/decode the file content.
    """

    data = reader.read()
    reader.close()

    return b64encode(data).decode()


def get_file_content(name: str = None, id_: str = None) -> Tuple[str, str]:

    """
    This function return a base64 of the file
    content and the filename (without check permissions).

    If id_ and name arguments are None this function return (None, None).

    Using a name this function return the last versions of the file content.
    Using an ID this function return the version of this ID.
    """

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

    if not exists(filename):
        raise FileNotFoundError(
            f"No such file or directory: {error_description}."
        )

    only_filename = split(file.name)[1]
    return get_content(file), only_filename


def get_file(name: str, id_: str = None) -> Tuple[List[Upload], Counter]:

    """
    This function return the history of a file.

    If name is None, this function get Upload by ID.
    """

    versions = []
    counter = Counter()

    for file in get_files():
        file = anti_XSS(file)
        counter[file.name] += 1
        if file.name == name or (name is None and id_ == file.ID):
            versions.append(file)

    return versions, counter


def get_real_file_name(filename: str, timestamp: float) -> str:

    """
    This function return the real filename of a file.
    """

    filename, extension = splitext(split(filename)[1])

    return join(
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
