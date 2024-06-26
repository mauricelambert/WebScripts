#!/usr/bin/env python
# -*- coding: utf-8 -*-

###################
#    This file can share a password securely
#    Copyright (C) 2021, 2022, 2023, 2024  Maurice Lambert

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

This file can share a password securely.
"""

__version__ = "1.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file can share a password securely.
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023, 2024  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = [
    "encrypt",
    "get_passwords",
    "save",
    "get_id",
    "get_printable",
    "main",
]

from secrets import token_bytes, randbelow
from csv import reader, writer, QUOTE_ALL
from os import path, chdir, environ
from sys import argv, exit, stderr
from hashlib import pbkdf2_hmac
from urllib.parse import quote
from typing import Tuple, List
from base64 import b64encode
from time import time


# csv format: timestamp,password,view_number,hash,iterations,id
filename = path.join("data", "passwords.csv")
file_id = path.join("data", "id")
SIZE = 60


def encrypt(password: str) -> Tuple[bytes, str, int, bytes]:
    """
    This function encrypts and hashes the password.
    """

    key = token_bytes(SIZE)
    cipher = []
    iteration = 9999 + randbelow(5001)
    encoded_password = []

    for i, car in enumerate(password):
        car = ord(car)
        encoded_password.append(car)
        cipher.append(key[i % SIZE] ^ car)

    hash_ = pbkdf2_hmac(
        "sha512", bytes(encoded_password), key, iteration
    ).hex()
    return bytes(cipher), hash_, iteration, key


def get_passwords() -> List[List[str]]:
    """
    This function returns a list of encrypted passwords.
    """

    with open(filename, newline="") as file:
        passwords = list(reader(file, quoting=QUOTE_ALL))
    return passwords


def save(passwords: List[List[str]], id_: int) -> None:
    """
    This function save passwords and ID.
    """

    with open(filename, "w", newline="") as file:
        csvfile = writer(file, quoting=QUOTE_ALL)
        for password in passwords:
            csvfile.writerow(password)

    with open(file_id, "w", newline="") as file:
        file.write(str(id_))


def get_id() -> int:
    """
    This function return the password ID.
    """

    if not path.isfile(file_id):
        with open(file_id, "w") as file:
            file.write("0")

    with open(file_id) as file:
        id_ = file.read()
    return int(id_) + 1


def get_printable(password: bytes, key: bytes) -> Tuple[str, str]:
    """
    This function return a printable password and key (using base64).
    """

    password = b64encode(password).decode()
    key = b64encode(key).decode()
    return password, key


def get_url(token: str) -> str:
    """
    This returns the relative URL to get
    the password share.
    """

    return "./get_password_share.py?token=" + quote(token)


def main() -> int:
    """
    Main function to add secure password sharing.
    """

    chdir(path.join(path.dirname(__file__), "..", ".."))

    if (
        len(argv) != 4
        or not argv[3].isdigit()
        or not argv[2].replace(".", "", 1).isdigit()
    ):
        print(
            "USAGE: python3 new_password_share.py [password string required] "
            "[time_in_hours float required] [maximum_number_of_views "
            "integer required]",
            file=stderr,
        )
        return 1

    password, hours, views = argv[1], float(argv[2]), int(argv[3])

    passwords = get_passwords()
    timestamp = time() + (hours * 3600)
    id_ = get_id()

    password, hash_, iteration, key = encrypt(password)
    password, key = get_printable(password, key)

    password = [timestamp, password, views, hash_, iteration, id_]

    for string in passwords:
        if isinstance(string, str) and not string.isprintable():
            print(
                f"Strings must be printable: {string!r} is not.", file=stderr
            )
            return 2

    passwords.append(password)
    save(passwords, id_)

    print(
        f'<a href="{get_url(f"{id_}:{key}")}">Click on this link or '
        "copy it to access to the password.</a>"
    )
    return 0


if __name__ == "__main__":
    exit(main())
