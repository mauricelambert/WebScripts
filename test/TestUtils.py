#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file test the WebScript.py file
#    from the command line and display the result in a web interface.
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

"""This file test the WebScripts.py file"""

from os import path, device_encoding, getcwd
from unittest import TestCase, main
from unittest.mock import Mock
from types import MethodType
from importlib import reload
from typing import List
from json import load
import platform
import locale
import json
import gzip
import sys
import os

sys.path = [path.join(path.dirname(__file__), ".."), *sys.path]

from WebScripts.utils import (
    DefaultNamespace,
    get_ip,
    get_arguments_count,
    get_file_content,
    get_real_path,
    get_encodings,
    get_ini_dict,
    MissingAttributesError,
    WebScriptsConfigurationError,
    LinuxLogs,
    WindowsLogs,
    Logs,
    log_trace,
    server_path,
    CustomLogHandler,
    # namer,
    # rotator,
)
import WebScripts.utils


class TestLinuxLogs(TestCase):  # Code coverage, no tests on Logs functions
    def setUp(self):
        WebScripts.utils.syslog = Mock(
            LOG_DEBUG=10, LOG_INFO=20, LOG_WARNING=30, LOG_ERR=40, LOG_CRIT=50
        )
        WebScripts.utils.ReportEvent = Mock()
        self.logs = LinuxLogs

    def test_debug(self):
        self.logs.debug("test")

    def test_info(self):
        self.logs.info("test")

    def test_warning(self):
        self.logs.warning("test")

    def test_error(self):
        self.logs.error("test")

    def test_critical(self):
        self.logs.critical("test")


class TestWindowsLogs(TestCase):  # Code coverage, no tests on Logs functions
    def setUp(self):
        WebScripts.utils.win32evtlog = Mock(
            EVENTLOG_INFORMATION_TYPE=10,
            EVENTLOG_WARNING_TYPE=20,
            EVENTLOG_ERROR_TYPE=30,
        )
        WebScripts.utils.ReportEvent = Mock()
        WebScripts.utils.WINDOWS_LOGS = True
        self.logs = WindowsLogs

    def test_debug(self):
        self.logs.debug("test")

    def test_info(self):
        self.logs.info("test")

    def test_warning(self):
        self.logs.warning("test")

    def test_error(self):
        self.logs.error("test")

    def test_critical(self):
        self.logs.critical("test")


class TestLogs(TestCase):  # Code coverage, no tests on Logs functions
    def test_exception(self):
        Logs.exception("test")


class TestDefaultNamespace(TestCase):
    def setUp(self):
        self.default_namespace = DefaultNamespace()

    def test_constructor(self):
        default_namespace = DefaultNamespace(default={"test": "test"})
        self.assertEqual(default_namespace.test, "test")

    def test_update(self):
        self.default_namespace.update(test="test")

        self.assertEqual(getattr(self.default_namespace, "test", None), "test")

        self.default_namespace.update(test="test1")

        self.assertEqual(
            getattr(self.default_namespace, "test", None), "test1"
        )

    def test_check_required(self):
        self.default_namespace.__required__ = ["test"]
        self.default_namespace.test = None

        with self.assertRaises(MissingAttributesError):
            self.default_namespace.check_required()

        del self.default_namespace.test

        with self.assertRaises(MissingAttributesError):
            self.default_namespace.check_required()

        self.default_namespace.test = "test"
        self.default_namespace.check_required()

    def test_get_missings(self):
        self.default_namespace.__required__ = ["test"]

        self.default_namespace.test = None
        self.assertListEqual(
            self.default_namespace.get_missings(),
            ["test"],
        )

        del self.default_namespace.test
        self.assertListEqual(
            self.default_namespace.get_missings(),
            ["test"],
        )

        self.default_namespace.test = "test"
        self.assertListEqual(
            self.default_namespace.get_missings(),
            [],
        )

    def test_get_unexpecteds(self):
        self.default_namespace.__required__ = []
        self.default_namespace.__optional__ = []

        self.default_namespace.test = "test"

        self.assertListEqual(
            self.default_namespace.get_unexpecteds(),
            ["test"],
        )

    def test_get_dict(self):
        self.default_namespace.method = MethodType(
            print, self.default_namespace
        )
        self.default_namespace.__required__ = ["test"]
        self.default_namespace.test = "test"

        self.assertDictEqual(
            self.default_namespace.get_dict(),
            {"test": "test"},
        )

    def test_export_as_json(self):
        self.default_namespace.test = "test"
        self.default_namespace.export_as_json()

        self.assertTrue(path.exists("export_DefaultNamespace.json"))

        with open("export_DefaultNamespace.json") as file:
            self.assertDictEqual(load(file), {"test": "test"})

        self.default_namespace.export_as_json("test.json")

        self.assertTrue(path.exists("test.json"))

        with open("test.json") as file:
            self.assertDictEqual(load(file), {"test": "test"})

        os.remove("export_DefaultNamespace.json")
        os.remove("test.json")

    def test_build_types(self):
        self.default_namespace.five_ = 5
        self.default_namespace.five = "5"
        self.default_namespace.null = None
        self.default_namespace.true_ = True
        self.default_namespace.true = "true"
        self.default_namespace.false_ = False
        self.default_namespace.false = "false"

        self.default_namespace.list = "a,b,c,d"
        self.default_namespace.listStr = "a,b,c,d"
        self.default_namespace.listInt = "1,2,3,4"

        self.default_namespace.__types__ = {
            "int": int,
            "five": int,
            "five_": int,
            "list": list,
            "bool": bool,
            "true": bool,
            "true_": bool,
            "false": bool,
            "false_": bool,
            "listStr": List[str],
            "listInt": List[int],
            "listError": List[int],
        }

        self.default_namespace.build_types()

        self.assertTrue(self.default_namespace.true)
        self.assertTrue(self.default_namespace.true_)
        self.assertIsNone(self.default_namespace.null)
        self.assertFalse(self.default_namespace.false)
        self.assertFalse(self.default_namespace.false_)
        self.assertEqual(self.default_namespace.five, 5)
        self.assertEqual(self.default_namespace.five_, 5)

        self.default_namespace.int = "error"
        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_types()
        self.default_namespace.int = "5"

        self.default_namespace.bool = "error"
        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_types()
        self.default_namespace.bool = "true"

        self.default_namespace.listError = "1,2,3,d"
        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_types()

    def test_set_default(self):
        self.default_namespace.__defaults__ = {
            "test": "value",
            "test1": "value",
        }

        self.default_namespace.test = "test"
        self.default_namespace.set_defaults()

        self.assertEqual(self.default_namespace.test, "test")
        self.assertEqual(self.default_namespace.test1, "value")

    def test_get(self):
        self.default_namespace.test = "test"
        self.assertEqual(
            self.default_namespace.get("test", "value"),
            "test",
        )

        self.assertEqual(
            self.default_namespace.get("test2", "value"),
            "value",
        )

    def test_getitem(self):
        self.default_namespace.test = "test"
        self.assertEqual(
            self.default_namespace["test"],
            "test",
        )


class TestCustomLogHandler(TestCase):
    def test_namer(self):
        self.assertEqual("test.gz", CustomLogHandler.namer(None, "test"))

    def test_rotator(self):
        current = getcwd()
        src = path.join(current, "test.txt")
        dest = path.join(current, "test.gz")

        with open(src, "w") as file:
            file.write("abc")

        CustomLogHandler.rotator(None, src, dest)

        self.assertFalse(path.exists(src))
        self.assertTrue(path.exists(dest))

        with open(dest, "rb") as file:
            self.assertEqual(gzip.decompress(file.read()), b"abc")

        os.remove("test.gz")


class TestFunctions(TestCase):
    def test_log_trace(self):  # Code coverage, no tests on Logs functions
        test = lambda: None
        static = staticmethod(test)
        log_trace(static)

    def test_no_pywin32(self):
        path_ = sys.path.copy()
        sys.path = [x for x in sys.path if not sys.prefix.lower() in x.lower()]
        sys.modules = {
            x: y for x, y in sys.modules.items() if not x.startswith("win32")
        }

        reload(WebScripts.utils)
        sys.path = path_

        # self.assertFalse(WebScripts.utils.WINDOWS_LOGS)

    def test_get_encodings(self):
        encodings = ["utf-8", "cp1252", "latin-1"]

        if device_encoding(0) is not None:
            encodings.insert(0, device_encoding(0))
        if locale.getpreferredencoding() is not None:
            encodings.insert(0, locale.getpreferredencoding())

        self.assertListEqual(
            list(get_encodings()),
            encodings,
        )

    def test_get_file_content(self):
        with open("test.json", "w") as file:
            file.write('{"test": "test"}')

        with open("test.json") as file:
            self.assertDictEqual(
                json.loads(get_file_content("test.json", encoding="latin-1")),
                json.load(file),
            )

        def generator():
            yield "ascii"

        WebScripts.utils.get_encodings = generator

        with open("test.txt", "wb") as file:
            file.write(bytes(range(256)))

        with self.assertRaises(Exception):
            get_file_content("test.txt")

        os.remove("test.txt")
        os.remove("test.json")

    def test_get_real_path(self):
        with open("test.json", "w") as file:
            file.write('{"test": "test"}')

        self.assertIsNone(get_real_path(None))
        self.assertEqual("test.json", get_real_path("test.json"))
        self.assertEqual(
            path.normcase(server_path + "/static/html/utils.html").lower(),
            get_real_path("static/html/utils.html").lower(),
        )

        if platform.system() == "Windows":
            self.assertEqual(
                r"C:\WINDOWS\system32\cmd.exe".lower(),
                get_real_path(r"C:\WINDOWS\system32\cmd.exe").lower(),
            )
        else:
            self.assertEqual(
                "/etc/passwd",
                get_real_path("/etc/passwd"),
            )

        with self.assertRaises(FileNotFoundError):
            get_real_path("test.test")

        os.remove("test.json")

    def test_get_ip(self):
        env = {
            "X_REAL_IP": "ip1",
            "X_FORWARDED_FOR": "ip2",
            "X_FORWARDED_HOST": "ip3",
            "REMOTE_ADDR": "ip4",
        }

        self.assertEqual(get_ip(env), "ip1")
        env.pop("X_REAL_IP")
        self.assertEqual(get_ip(env), "ip2")
        env.pop("X_FORWARDED_FOR")
        self.assertEqual(get_ip(env), "ip3")
        env.pop("X_FORWARDED_HOST")
        self.assertEqual(get_ip(env), "ip4")

    def test_get_ini_dict(self):

        with open("test.ini", "w") as file:
            file.write("[test]\ntest=test")

        self.assertDictEqual(
            {"test": {"test": "test"}}, get_ini_dict("test.ini")
        )

        os.remove("test.ini")

    def test_get_arguments_count(self):
        test = os.mkdir
        self.assertEqual(7, get_arguments_count(test))

        def methodTest0():
            pass

        def methodTest2(a, b):
            pass

        def methodTest3(a, b, c, *args, **kwargs):
            pass

        def methodTest5(a, b, c, *args, d=3, e="", **kwargs):
            pass

        def methodTest6(a, b, c, *, d=0, e="", f=None):
            pass

        self.assertEqual(0, get_arguments_count(methodTest0))
        self.assertEqual(2, get_arguments_count(methodTest2))
        self.assertEqual(6, get_arguments_count(methodTest6))
        self.assertEqual(3, get_arguments_count(methodTest3))
        self.assertEqual(5, get_arguments_count(methodTest5))


if __name__ == "__main__":
    main()
