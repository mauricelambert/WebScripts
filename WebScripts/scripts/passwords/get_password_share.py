#!/usr/bin/env python
# -*- coding: utf-8 -*-

###################
#    This file can decrypt and print a secure password share
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

This file can decrypt and print a secure password share."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file can decrypt and print a secure password share."""
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

__all__ = ["save", "delete", "decrypt", "get_passwords", "main"]

from typing import TypeVar, Tuple, List
from hashlib import pbkdf2_hmac
from csv import reader, writer
from base64 import b64decode
from os import path, chdir
from time import time
from sys import argv
import sys

PasswordOrFalse = TypeVar("PasswordOrFalse", str, bool)
PasswordInfo = TypeVar("PasswordInfo", str, int, bool)
filename = path.join("data", "passwords.csv")


def decrypt(key: bytes, password: bytes, hash_: str, iteration: int) -> PasswordOrFalse:

    """This function checks the integrity of the
    password and returns the decrypted password."""

    password_ = ""
    key_length = len(key)
    for i, car in enumerate(password):
        password_ += chr(key[i % key_length] ^ car)

    if pbkdf2_hmac("sha512", password_.encode(), key, int(iteration)).hex() == hash_:
        return password_
    else:
        return False


def get_passwords(
    id_: int,
) -> Tuple[List[List[PasswordInfo]], List[PasswordInfo]]:

    """This function returns a list of passwords
    and the requested password."""

    now = time()
    password_ = None

    with open(filename, newline="") as file:
        passwords = list(reader(file))

        for password in passwords:
            if float(password[0]) >= now:
                password.append(True)
            else:
                password.append(False)

            if id_ == int(password[5]):
                password_ = password

        return passwords, password_


def main() -> None:

    """Main function to obtain secure password sharing:
    - Check the validity of the token
    - Check the validity of the password
    - Print password or error message"""

    chdir(path.join(path.dirname(__file__), "..", ".."))

    if len(argv) != 2:
        print("USAGE: python3 get_password_share.py [token string required]")
        sys.exit(1)

    token = sys.argv[1]
    bad_token = ":" not in token

    if not bad_token:
        id_, key = token.split(":")
        bad_token = not id_.isdigit()

    if bad_token:
        print("TOKEN ERROR: Token is not valid.")
        sys.exit(2)

    id_ = int(id_)
    key = key.encode()

    passwords, password = get_passwords(id_)

    if not password:
        print("TOKEN ERROR: the password for this token does not exist.")
        sys.exit(3)

    if password[-1]:
        password_ = decrypt(
            b64decode(key), b64decode(password[1]), password[3], password[4]
        )
    else:
        print("TIME ERROR: The password for this token is no longer available.")
        sys.exit(4)

    if not password_:
        print("TOKEN ERROR: Bad key.")
        sys.exit(5)

    password[2] = int(password[2])

    if password[2]:
        password[2] -= 1
    else:
        print(
            "VIEWS ERROR: This password has been requested too many times, you can no longer access it."
        )
        sys.exit(6)

    passwords = delete(passwords)
    save(passwords)

    print(password_)


def delete(passwords: List[List[PasswordInfo]]) -> List[List[PasswordInfo]]:

    """This function delete old passwords."""

    for password in passwords:
        if not password[-1]:
            passwords.remove(password)
    return passwords


def save(passwords: List[List[PasswordInfo]]) -> None:

    """This function re-saves passwords."""

    with open(filename, "w", newline="") as file:
        csvfile = writer(file)
        for password in passwords:
            csvfile.writerow(password[:-1])


if __name__ == "__main__":
    main()
    sys.exit(0)
