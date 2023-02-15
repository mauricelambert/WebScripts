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

This file implements a RSS feed.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file implements a RSS feed.
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

from typing import Tuple, Dict, List, TypeVar, Iterable
from csv import writer, DictReader, QUOTE_ALL
from time import strftime, localtime
from os.path import join
from os import _Environ
from io import StringIO
from json import dumps
from enum import Enum

Server = TypeVar("Server")
User = TypeVar("User")


class FIELDS(Enum):
    guid = 0
    author = 1
    title = 2
    description = 3
    link = 4
    categories = 5
    pubDate = 6
    comments = 7


def get_rss_path(server: Server) -> str:
    """
    This function returns the rss path.
    """

    return join(server.configuration.data_dir, "rss.csv")


class Feed:

    """
    This class implements the RSS feed.
    """

    rss_path: str = None

    required: List[str] = ["title", "description", "link", "categories"]
    optional: List[str] = ["comments"]
    default: List[str] = ["author", "guid", "pubDate", "lastBuildDate"]

    @classmethod
    def csv(
        cls: type,
        environ: _Environ,
        user: User,
        server: Server,
        category: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function prints the RSS feed content as CSV.
        """

        rss_path = cls.rss_path = cls.rss_path or get_rss_path(server)

        if not category:
            with open(rss_path, "r") as file:
                data = file.read()

            return (
                "200 OK",
                {"Content-Type": "text/csv"},
                data,
            )

        data = StringIO()
        writerow = writer(data, quoting=QUOTE_ALL).writerow

        with open(
            join(server.configuration.data_dir, "rss.csv"), "r", newline=""
        ) as csvfile:
            writerow(
                [
                    "guid",
                    "author",
                    "title",
                    "description",
                    "link",
                    "categories",
                    "pubDate",
                    "comments",
                ]
            )
            [
                writerow(row.values())
                for row in DictReader(csvfile)
                if category in row["categories"].split(",")
            ]

        data.seek(0)

        return (
            "200 OK",
            {"Content-Type": "text/csv; charset=utf-8"},
            data.read(),
        )

    @classmethod
    def json(
        cls: type,
        environ: _Environ,
        user: User,
        server: Server,
        category: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function prints the RSS feed content as JSON.
        """

        rss_path = cls.rss_path = cls.rss_path or get_rss_path(server)

        with open(rss_path, "r", newline="") as file:
            data = dumps(
                [
                    row
                    for row in DictReader(file)
                    if not category or category in row["categories"].split(",")
                ]
            )

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            data,
        )

    def __new__(
        cls: type,
        environ: _Environ,
        user: User,
        server: Server,
        category: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Iterable[bytes]]:
        """
        This function prints the RSS feed.
        """

        full_url = server.get_fullurl(environ)
        base_url = server.get_baseurl(environ.get, environ)
        rss_path = cls.rss_path = cls.rss_path or get_rss_path(server)

        data = cls.generator(full_url, base_url, rss_path, category)

        return (
            "200 OK",
            {"Content-Type": "application/xml; charset=utf-8"},
            data,
        )

    @classmethod
    def generator(
        cls: type, full_url: str, base_url: str, rss_path: str, category: str
    ) -> Iterable[bytes]:
        """
        This generator returns RSS feed content.
        """

        def get_date(timestamp: str) -> str:
            return strftime("%a, %d %b %Y %X %z", localtime(float(timestamp)))

        file = open(rss_path, "r", newline="")
        csvreader = DictReader(file)

        for item in csvreader:
            pass

        last_time = get_date(item["pubDate"])

        file.seek(0)
        csvreader = DictReader(file)

        yield f"""<?xml version='1.0' encoding='UTF-8'?>
<rss xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:wfw="http://wellformedweb.org/CommentAPI/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:sy="http://purl.org/rss/1.0/modules/syndication/" xmlns:slash="http://purl.org/rss/1.0/modules/slash/" version="2.0">
    <channel>
        <title>WebScripts</title>
        <atom:link href="{full_url}" rel="self" type="application/rss+xml"/>
        <link>{base_url}</link>
        <description>
            RSS feed of WebScripts Server to
            manage systems, accounts and networks.
        </description>
        <lastBuildDate>{last_time}</lastBuildDate>
        <language>en-US</language>
        <sy:updatePeriod>hourly</sy:updatePeriod>
        <sy:updateFrequency>1</sy:updateFrequency>""".encode()

        for item in csvreader:
            categories = item.pop("categories")
            if not category or category in categories:
                yield (
                    f"""
        <item>
            <title>%(title)s</title>
            <author>%(author)s</author>
            <comments>%(comments)s</comments>
            <link>%(link)s</link>
            <pubDate>{get_date(item.pop("pubDate"))}</pubDate>
            <guid isPermaLink="true">%(guid)s</guid>
            <description>%(description)s</description>
            {
                ''.join(f'<category>{category}</category>'
                for category in categories.split(','))
            }
        </item>
                """
                    % item
                ).encode()

        yield """
    </channel>
</rss>""".encode()

        file.close()
