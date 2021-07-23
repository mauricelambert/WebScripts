#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implement some functions to manage WebScript default databases
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

This file implement some functions to manage WebScript default databases."""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file implement some functions to manage WebScript default databases"""
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
    "User",
    "Group",
    "add_user",
    "add_group",
    "get_users",
    "UserError",
    "GroupError",
    "get_groups",
    "get_apikey",
    "delete_user",
    "delete_group",
    "change_user_password",
    "create_default_databases",
]

from secrets import randbelow, token_bytes
from base64 import b64encode, b64decode
from collections.abc import Iterator
from os import environ, path, chdir
from collections import namedtuple
from hashlib import pbkdf2_hmac
from fnmatch import fnmatch
from typing import List
import csv

User = namedtuple(
    "User",
    ["ID", "name", "password", "salt", "enumerations", "IPs", "groups", "apikey"],
)
Group = namedtuple("Group", ["ID", "name"])
FILES = ("users.csv", "groups.csv")
DIRECTORY = "data"


class UserError(Exception):

    """This class can raise a UserError."""


class GroupError(Exception):

    """This class can raise a GroupError."""


def get_users() -> Iterator[User]:

    """This function get users from CSV database."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))
    yield from map(
        User._make, csv.reader(open(path.join(DIRECTORY, FILES[0]), "r", newline=""))
    )


def get_groups() -> Iterator[Group]:

    """This function get groups from CSV database."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))
    yield from map(
        Group._make, csv.reader(open(path.join(DIRECTORY, FILES[1]), "r", newline=""))
    )


def get_apikey(id_: str, password: str) -> str:

    """This function returns the API key after verification of authentication."""

    for user in get_users():
        if id_ == user.ID:
            user = auth_username_password(user.name, password)

            if user.ID == "0":
                return None

            return user.apikey


def change_user_password(id_: str, new_password: str, old_password: str = None) -> User:

    """This function change a user password."""

    users = []
    user_ = None

    for user in get_users():
        if id_ == user.ID:
            user_ = user

            if (
                old_password is not None
                and auth_username_password(user.name, old_password)[0] != "0"
            ) or old_password is None:
                enumerations = 90000 + randbelow(20000)
                salt = token_bytes(32)
                password = b64encode(
                    pbkdf2_hmac("sha512", new_password.encode(), salt, enumerations)
                ).decode()

                user = user._replace(
                    password=password,
                    enumerations=str(enumerations),
                    salt=b64encode(salt).decode(),
                    apikey=b64encode(token_bytes(125)).decode(),
                )

            else:
                user_ = False

        users.append(user)

    rewrite_users(users)
    return user_


def add_user(
    name: str, password: str, groups: List[int], ips: List[str] = ["*"]
) -> User:

    """This function add user in database or raise a UserError."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))

    for i, user in enumerate(get_users()):
        if name == user.name:
            raise UserError(f'unique constraint failed: name "{name}" is used')

    enumerations = 90000 + randbelow(20000)
    salt = token_bytes(32)
    hash_ = b64encode(
        pbkdf2_hmac("sha512", password.encode(), salt, enumerations)
    ).decode()
    user = User(
        str(i),
        name,
        hash_,
        b64encode(salt).decode(),
        str(enumerations),
        ",".join(ips),
        ",".join([str(group) for group in groups]),
        b64encode(token_bytes(125)).decode(),
    )

    with open(path.join(DIRECTORY, FILES[0]), "a", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(user)

    return user


def auth_username_password(name: str, password: str) -> User:

    """This function verifies the authentication
    with user name and password."""

    for user in get_users():
        if (
            user.password
            and user.name == name
            and b64encode(
                pbkdf2_hmac(
                    "sha512",
                    password.encode(),
                    b64decode(user.salt.encode()),
                    int(user.enumerations),
                )
            ).decode()
            == user.password
        ):
            for glob_ip in user.IPs.split(","):
                if fnmatch(environ["REMOTE_ADDR"], glob_ip):
                    return user

    return User("0", "Not Authenticated", "", "", "", "*", "0", "")


def auth_apikey(apikey: str) -> User:

    """This function verifies the authentication
    with api key."""

    for user in get_users():
        if apikey == user.apikey:
            return user

    return User("0", "Not Authenticated", "", "", "", "*", "0", "")


def auth(username: str = None, password: str = None, apikey: str = None) -> User:

    """This function returns a User from credentials
    (username and password) or an api key."""

    if apikey is None:
        return auth_username_password(username, password)
    else:
        return auth_apikey(apikey)


def add_group(name: str, id_: int) -> Group:

    """This function add group in database or raise a GroupError."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))

    for group in get_groups():
        if name == group.name:
            raise GroupError(f'unique constraint failed: name "{name}" is used')
        elif id_ == group.ID:
            raise GroupError(f"unique constraint failed: ID {id_} is used")

    group = Group(id_, name)

    with open(path.join(DIRECTORY, FILES[1]), "a", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(group)

    return group


def delete_user(id_: int) -> User:

    """This function delete a user by id and return the deleted user."""

    users = []
    deleted_user = None

    for user in get_users():
        if user.ID != "ID" and int(user.ID) == id_:
            deleted_user = user
        else:
            users.append(user)

    rewrite_users(users)

    return deleted_user


def rewrite_users(users: List[User]) -> None:

    """This function rewrite a list of User."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))

    with open(path.join(DIRECTORY, FILES[0]), "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        # csv_writer.writerow(User._fields)
        for user in users:
            csv_writer.writerow(user)


def delete_group(id_: int) -> Group:

    """This function delete a group by id and return the deleted group."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))

    groups = []
    deleted_group = None

    for group in get_groups():
        if group.ID != "ID" and int(group.ID) == id_:
            deleted_group = group
        else:
            groups.append(group)

    with open(path.join(DIRECTORY, FILES[1]), "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        # csv_writer.writerow(Group._fields)
        for group in groups:
            csv_writer.writerow(group)

    return deleted_group


def create_default_databases() -> None:

    """This function create defaults users and groups."""

    chdir(path.join(path.dirname(__file__), "..", "..", ".."))

    default_users = [
        User("0", "Not Authenticated", "", "", "", "*", "0", ""),
        User("1", "Unknow", "", "", "", "*", "0,1", ""),
        User(
            "2",
            "Admin",
            "pZo8c8+cKLTHFaUBxGwcYaFDgNRw9HHph4brixOo6OMusFKbfkBEObZiNwda/f9W3+IpiMY8kqiFmQcbkUCbGw==",
            "c2FsdA==",
            "1000",
            "192.168.*,172.16.*,10.*,127.0.*",
            "50,1000",
            "Admin" * 32,
        ),
    ]
    default_groups = [
        Group("0", "Not Authenticated"),
        Group("1", "Unknow"),
        Group("50", "User"),
        Group("500", "Developers"),
        Group("750", "Maintainers"),
        Group("1000", "Administrators"),
    ]

    with open(
        path.join(DIRECTORY, FILES[0]), "w", newline=""
    ) as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(User._fields)
        for user in default_users:
            csv_writer.writerow(user)

    with open(
        path.join(DIRECTORY, FILES[1]), "w", newline=""
    ) as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(Group._fields)
        for group in default_groups:
            csv_writer.writerow(group)


if __name__ == "__main__":
    create_default_databases()
