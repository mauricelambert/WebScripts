#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file implement some functions to manage WebScript default databases
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

This file implement some functions to manage WebScript default databases.
"""

__version__ = "2.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file implements functions to manage WebScript default user database
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
    "get_dict_groups",
    "change_user_password",
    "create_default_databases",
]

from secrets import randbelow, token_bytes
from csv import reader, writer, QUOTE_ALL
from base64 import b64encode, b64decode
from collections.abc import Iterator
from typing import List, Dict, Union
from collections import namedtuple
from hmac import compare_digest
from hashlib import pbkdf2_hmac
from fnmatch import fnmatch
from os.path import join
from html import escape
from os import environ

User = namedtuple(
    "User",
    [
        "ID",
        "name",
        "password",
        "salt",
        "enumerations",
        "IPs",
        "groups",
        "apikey",
        "categories",
        "scripts",
    ],
)
Group = namedtuple("Group", ["ID", "name"])
DIRECTORY = environ["WEBSCRIPTS_DATA_PATH"]
USERFILE = "users.csv"
GROUPFILE = "groups.csv"


class UserError(Exception):
    """
    This class can raise a UserError.
    """


class GroupError(Exception):
    """
    This class can raise a GroupError.
    """


def upgrade_database() -> None:
    """
    This function upgrade the database.

    Add default categories ("*")
    Add default scripts    ("*")
    """

    users = []
    user_add = users.append
    first = True

    with open(join(DIRECTORY, USERFILE), newline="") as csvfile:
        csvreader = reader(csvfile, quoting=QUOTE_ALL)

        for row in csvreader:
            if len(row) == 8:
                row_add = row.append
                if first:
                    row_add("categories")
                    row_add("scripts")
                    first = False
                else:
                    row_add("*")
                    row_add("*")

            user_add(row)

    with open(join(DIRECTORY, USERFILE), "w", newline="") as csvfile:
        csvwriter = writer(csvfile, quoting=QUOTE_ALL)
        writerow = csvwriter.writerow
        [writerow(user) for user in users]


def get_users() -> Iterator[User]:
    """
    This function get users from CSV database.
    """

    yield from map(
        User._make,
        reader(
            open(join(DIRECTORY, USERFILE), "r", newline=""),
            quoting=QUOTE_ALL,
        ),
    )


def get_groups() -> Iterator[Group]:
    """
    This function get groups from CSV database.
    """

    yield from map(
        Group._make,
        reader(
            open(join(DIRECTORY, GROUPFILE), "r", newline=""),
            quoting=QUOTE_ALL,
        ),
    )


def get_dict_groups(by_name: bool = False) -> Dict[str, str]:
    """
    This function returns the dict of groups (ID: Name or Name: ID).
    """

    if by_name:
        return {
            n: i
            for i, n in reader(
                open(join(DIRECTORY, GROUPFILE), "r", newline=""),
                quoting=QUOTE_ALL,
            )
        }
    return {
        i: n
        for i, n in reader(
            open(join(DIRECTORY, GROUPFILE), "r", newline=""),
            quoting=QUOTE_ALL,
        )
    }


def get_apikey(id_: str, password: str) -> str:
    """
    This function returns the API key after verification of authentication.
    """

    for user in get_users():
        if id_ == user.ID:
            user = auth_username_password(user.name, password)

            if not user or user.ID == "0":
                return None

            return escape(user.apikey)


def anti_XSS(named_tuple: namedtuple) -> namedtuple:
    """
    This function returns a namedtuple without HTML special characters.
    """

    if not named_tuple:
        return named_tuple

    new = {}
    for attribut, value in named_tuple._asdict().items():
        new[attribut] = escape(value)
    return named_tuple.__class__(**new)


def change_user_password(
    id_: str, new_password: str, old_password: str = None
) -> User:
    """
    This function change a user password.
    """

    users = []
    user_ = None
    has_old_password = old_password is not None

    for user in get_users():
        if id_ == user.ID:
            user_ = has_old_password and auth_username_password(
                user.name, old_password
            )
            modify_password = (
                has_old_password
                and user_
                and user_[0] != "0"
                and user_[0] != "1"
            ) or not has_old_password
            if modify_password:
                enumerations = 90000 + randbelow(20000)
                salt = token_bytes(32)
                password = b64encode(
                    pbkdf2_hmac(
                        "sha512", new_password.encode(), salt, enumerations
                    )
                ).decode()

                user = user._replace(
                    password=password,
                    enumerations=str(enumerations),
                    salt=b64encode(salt).decode(),
                    apikey=b64encode(token_bytes(125)).decode(),
                )
            else:
                raise PermissionError("Password is incorrect.")

        users.append(user)

    if modify_password:
        rewrite_users(users)

    return anti_XSS(user_)


def add_user(
    name: str,
    password: str,
    groups: List[int],
    ips: List[str] = ["*"],
    categories: List[str] = ["*"],
    scripts: List[str] = ["*"],
) -> User:
    """
    This function add user in database or raise a UserError.
    """

    name = escape(name)
    for i, user in enumerate(get_users()):
        if name == user.name:
            raise UserError(f"unique constraint failed: name {name!r} is used")

    enumerations = 90000 + randbelow(20000)
    salt = token_bytes(32)
    hash_ = b64encode(
        pbkdf2_hmac("sha512", password.encode(), salt, enumerations)
    ).decode()
    user = anti_XSS(
        User(
            str(i),
            name,
            hash_,
            b64encode(salt).decode(),
            str(enumerations),
            ",".join(ips),
            ",".join([str(group) for group in groups]),
            b64encode(token_bytes(125)).decode(),
            ",".join(categories),
            ",".join(scripts),
        )
    )

    for string in user:
        if not string.isprintable():
            raise ValueError(f"Strings must be printable: '{string}' is not.")

    with open(join(DIRECTORY, USERFILE), "a", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        csv_writer.writerow(user)

    return user


def check_ip(user: User) -> Union[User, None]:
    """
    This function performs an IP address
    filtering for authentication.
    """

    ip_addresses = environ["REMOTE_IP"].split(", ")

    for glob_ip in user.IPs.split(","):
        for ip in ip_addresses:
            if fnmatch(ip, glob_ip):
                return anti_XSS(user)


def auth_username_password(name: str, password: str) -> User:
    """
    This function verifies the authentication
    with user name and password.
    """

    name = escape(name)
    for user in get_users():
        if (
            user.password
            and user.name == name
            and compare_digest(
                pbkdf2_hmac(
                    "sha512",
                    password.encode(),
                    b64decode(user.salt.encode()),
                    int(user.enumerations),
                ),
                b64decode(user.password),
            )
        ):
            return check_ip(user)


def auth_apikey(apikey: str) -> User:
    """
    This function verifies the authentication
    with api key.
    """

    for user in get_users():
        if apikey == user.apikey:
            return check_ip(user)


def auth(
    username: str = None, password: str = None, api_key: str = None
) -> User:
    """
    This function returns a User from credentials
    (username and password) or an api key.
    """

    if api_key is None:
        user = auth_username_password(username, password)
    else:
        user = auth_apikey(api_key)

    if user is None:
        return User(
            "0", "Not Authenticated", "", "", "", "*", "0", "", "*", "*"
        )
    else:
        return user


def add_group(name: str, id_: int) -> Group:
    """
    This function add group in database or raise a GroupError.
    """

    for group in get_groups():
        if name == group.name:
            raise GroupError(
                f'unique constraint failed: name "{name}" is used'
            )
        elif id_ == group.ID:
            raise GroupError(f"unique constraint failed: ID {id_} is used")

    group = anti_XSS(Group(id_, name))

    for string in group:
        if not string.isprintable():
            raise ValueError(f"Strings must be printable: '{string}' is not.")

    with open(join(DIRECTORY, GROUPFILE), "a", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        csv_writer.writerow(group)

    return group


def delete_user(id_: int) -> User:
    """
    This function delete a user by id and return the deleted user.
    """

    users = []
    deleted_user = None

    for user in get_users():
        user_id = user.ID
        if user_id != "ID" and int(user_id) == id_:
            deleted_user = user
            users.append(
                User(
                    user_id,
                    "",
                    "",
                    "",
                    "0",
                    "",
                    "",
                    "",
                    "",
                    "",
                )
            )
        else:
            users.append(user)

    rewrite_users(users)

    return anti_XSS(deleted_user)


def rewrite_users(users: List[User]) -> None:
    """
    This function rewrite a list of User.
    """

    with open(join(DIRECTORY, USERFILE), "w", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        # csv_writer.writerow(User._fields)
        writerow = csv_writer.writerow
        [writerow(anti_XSS(user)) for user in users]


def delete_group(id_: int) -> Group:
    """
    This function delete a group by id and return the deleted group.
    """

    groups = []
    deleted_group = None

    for group in get_groups():
        group_id = group.ID
        if group_id != "ID" and int(group_id) == id_:
            deleted_group = group
        else:
            groups.append(group)

    with open(join(DIRECTORY, GROUPFILE), "w", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        # csv_writer.writerow(Group._fields)
        writerow = csv_writer.writerow
        [writerow(anti_XSS(group)) for group in groups]

    return anti_XSS(deleted_group)


def create_default_databases() -> None:
    """
    This function create defaults users and groups.
    """

    default_users = [
        User("0", "Not Authenticated", "", "", "", "*", "0", "", "*", "*"),
        User("1", "Unknow", "", "", "", "*", "0,1", "", "*", "*"),
        User(
            "2",
            "Admin",
            "pZo8c8+cKLTHFaUBxGwcYaFDgNRw9HHph4brixOo"
            "6OMusFKbfkBEObZiNwda/f9W3+IpiMY8kqiFmQcbkUCbGw==",
            "c2FsdA==",
            "1000",
            "192.168.*,172.16.*,10.*,127.0.*",
            "50,1000",
            "Admin" * 32,
            "*",
            "*",
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

    with open(join(DIRECTORY, USERFILE), "w", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        writerow = csv_writer.writerow

        writerow(User._fields)
        [writerow(user) for user in default_users]

    with open(join(DIRECTORY, GROUPFILE), "w", newline="") as csvfile:
        csv_writer = writer(csvfile, quoting=QUOTE_ALL)
        writerow = csv_writer.writerow

        writerow(Group._fields)
        [writerow(group) for group in default_groups]


if __name__ == "__main__":
    create_default_databases()

try:
    for user in get_users():
        break
except TypeError:
    upgrade_database()
