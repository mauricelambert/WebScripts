#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file tests the WebScript.py file
#    from the command line and display the result in a web interface.
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
This file tests the Utils.py file
"""

from os import path, device_encoding, getcwd
from unittest.mock import Mock, patch, call
from unittest import TestCase, main
from types import MethodType
from importlib import reload
from os.path import abspath
from platform import system
from typing import List
from io import StringIO
from json import load
import locale
import json
import gzip
import sys
import os

WebScripts_path = path.join(path.dirname(__file__), "..")

if WebScripts_path not in sys.path:
    sys.path.insert(0, WebScripts_path)

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
    check_file_permission,
)
import WebScripts.utils


class TestLinuxLogs(TestCase):  # Code coverage, no tests on Logs functions
    def setUp(self):
        WebScripts.utils.LOG_DEBUG = 10
        WebScripts.utils.LOG_INFO = 20
        WebScripts.utils.LOG_WARNING = 30
        WebScripts.utils.LOG_ERR = 40
        WebScripts.utils.LOG_CRIT = 50
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

    def test_access(self):
        self.logs.access("test")

    def test_response(self):
        self.logs.response("test")

    def test_command(self):
        self.logs.command("test")


class TestWindowsLogs(TestCase):  # Code coverage, no tests on Logs functions
    def setUp(self):
        WebScripts.utils.EVENTLOG_INFORMATION_TYPE = 10
        WebScripts.utils.EVENTLOG_WARNING_TYPE = 20
        WebScripts.utils.EVENTLOG_ERROR_TYPE = 30
        WebScripts.utils.ReportEvent = Mock()
        WebScripts.utils.WINDOWS_LOGS = True
        WebScripts.utils.SID = "test"
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

    def test_access(self):
        self.logs.access("test")

    def test_response(self):
        self.logs.response("test")

    def test_command(self):
        self.logs.command("test")


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

    def test_build_type(self):
        self.default_namespace.__types__ = {
            "ListInt": List[int],
            "ListStr": List[str],
            "ListFloat": List[float],
            "ListError": List[int],
            "List": List[int],
            "float": float,
            "error": int,
            "none": None,
            "int": int,
        }

        self.default_namespace.build_type("int", 1)
        self.default_namespace.build_type("float", 1)
        self.default_namespace.build_type("none", None)
        self.default_namespace.build_type("other", None)
        self.default_namespace.build_type("ListInt", 1)
        self.assertEqual(self.default_namespace.ListInt, [1])
        self.default_namespace.build_type("ListInt", ["1", "2"])
        self.default_namespace.build_type("ListFloat", "0.2,0.3")

        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_type(
                "ListError", 1 + 2j
            )  # complex(1,0)

        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_type("error", 1 + 2j)

        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_type("List", [1, "1", 1 + 2j])

        with self.assertRaises(WebScriptsConfigurationError):
            self.default_namespace.build_type("ListStr", ["1", 1 + 2j])

        self.assertEqual(self.default_namespace.int, 1)
        self.assertEqual(self.default_namespace.float, 1.0)
        self.assertEqual(self.default_namespace.ListInt, [1, 2])
        self.assertEqual(self.default_namespace.ListFloat, [0.2, 0.3])
        self.assertEqual(self.default_namespace.none, "None")
        self.assertEqual(self.default_namespace.other, "None")

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
    def test_doRollover(self):
        a = open("test.txt", "w")
        a.close()

        test = Mock(
            backupCount=5,
            stream=StringIO(),
            baseFilename="test.txt",
            rotation_filename=lambda x: x,
            delay=True,
        )

        with patch.object(test, "rotate", return_value=None) as mock:
            CustomLogHandler.doRollover(test)

        mock.assert_called_once_with("test.txt", "test.txt.1")
        os.remove("test.txt")

        self.assertIsNone(test.stream)

        test.delay = None
        CustomLogHandler.doRollover(test)
        self.assertIsInstance(test.stream, Mock)

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
        encodings = ["utf-8", "cp1252", "latin-1", None]

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

        with patch.object(
            WebScripts.utils,
            "get_encodings",
            return_value=(x for x in ["ascii", None]),
        ) as mock_method:
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
        self.assertEqual(abspath("test.json"), get_real_path("test.json"))
        self.assertEqual(
            abspath(
                path.normcase(server_path + "/static/html/utils.html").lower()
            ),
            get_real_path("static/html/utils.html").lower(),
        )

        if system() == "Windows":
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

        WebScripts.utils.system = (
            "Linux" if system() == "Windows" else "Windows"
        )
        WebScripts.utils.IS_WINDOWS = (
            False if WebScripts.utils.IS_WINDOWS else True
        )

        with self.assertRaises(FileNotFoundError):
            get_real_path("test.test")

        self.assertIsNone(get_real_path("test.test", no_error=True))

    def test_get_ip(self):
        env = {
            "HTTP_X_FORWARDED_FOR": "ip1, ipX",
            "HTTP_X_REAL_IP": "ip2",
            "HTTP_X_FORWARDED_HOST": "ip3",
            "HTTP_CLIENT_IP": "ip4",
            "REMOTE_ADDR": "ip5",
        }

        self.assertIsNone(get_ip(env, 5))

        env["HTTP_X_FORWARDED_FOR"] = "ip1"

        self.assertIsNone(get_ip(env, 2))
        self.assertIsNotNone(get_ip(env, 5))

        self.assertEqual(get_ip(env, None), "ip1, ip2, ip3, ip4, ip5")
        self.assertEqual(get_ip(env, None, False), "ip1")
        env.pop("HTTP_X_FORWARDED_FOR")
        self.assertEqual(get_ip(env, None), "ip2, ip3, ip4, ip5")
        self.assertEqual(get_ip(env, None, False), "ip2")
        env.pop("HTTP_X_REAL_IP")
        self.assertEqual(get_ip(env, None), "ip3, ip4, ip5")
        self.assertEqual(get_ip(env, None, False), "ip3")
        env.pop("HTTP_X_FORWARDED_HOST")
        self.assertEqual(get_ip(env, 2), "ip4, ip5")
        self.assertEqual(get_ip(env, 2, False), "ip4")
        env.pop("HTTP_CLIENT_IP")
        self.assertEqual(get_ip(env, 1), "ip5")
        self.assertEqual(get_ip(env, 1, False), "ip5")

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

        class Test:
            def __call__(self):
                pass

            def test(self):
                pass

        self.assertEqual(0, get_arguments_count(methodTest0))
        self.assertEqual(2, get_arguments_count(methodTest2))
        self.assertEqual(6, get_arguments_count(methodTest6))
        self.assertEqual(3, get_arguments_count(methodTest3))
        self.assertEqual(5, get_arguments_count(methodTest5))
        self.assertEqual(1, get_arguments_count(Test()))
        self.assertEqual(1, get_arguments_count(Test().test))
        self.assertEqual(1, get_arguments_count(Test.test))
        self.assertEqual(1, get_arguments_count(lambda x: x))

    def test_check_file_permission(self):
        WebScripts.utils.IS_WINDOWS = True
        self.assertTrue(
            check_file_permission(None, "test", False, False, False)
        )

        WebScripts.utils.IS_WINDOWS = False
        config = DefaultNamespace()
        config.force_file_permissions = False

        self.assertTrue(
            check_file_permission(config, "test", False, False, False)
        )

        config = DefaultNamespace()
        config.force_file_permissions = True

        class SpecificMock(Mock):
            first = True
            st_uid = 0

            @property
            def st_mode(self):
                first = self.first
                self.first = False
                return 33024 if first else 16877
                16877  # 0o040755 = 0o0400 + 0o0200 + 0o100 + 0o0040 + 0o0010 + 0o0004 + 0o0001 + 0o040000
                33024  # 0o100400 = 0o0400 + 0o100000

        stat_response = SpecificMock()

        user = WebScripts.utils.user
        getpwuid = getattr(WebScripts.utils, "getpwuid", None)

        WebScripts.utils.user = "root"
        WebScripts.utils.getpwuid = (
            lambda x: Mock(pw_name="root") if x == 0 else Mock()
        )

        class SpecialMock(Mock):
            def __call__(self, file):
                super().__call__(file)
                return file == "test/test"

        isfile = WebScripts.utils.isfile
        mock = WebScripts.utils.isfile = SpecialMock()

        with patch.object(
            WebScripts.utils, "stat", return_value=stat_response
        ) as file, patch.object(
            WebScripts.utils, "isdir", return_value=True
        ) as mock2:
            self.assertTrue(
                check_file_permission(config, "test/test", False, False, True)
            )
            self.assertEqual(mock.call_count, 2)
            self.assertListEqual(
                mock.call_args_list, [call("test/test"), call("test")]
            )
            mock2.assert_called_once()

            stat_response = DefaultNamespace()
            stat_response.st_uid = 0
            stat_response.st_mode = (
                33088  # 0o100500 = 0o0400 + 0o100 + 0o100000
            )

            file.return_value = stat_response

            self.assertTrue(
                check_file_permission(config, "test/test", False, True, False)
            )
            self.assertEqual(mock.call_count, 3)
            self.assertListEqual(
                mock.call_args_list,
                [call("test/test"), call("test"), call("test/test")],
            )
            mock2.assert_called_once()

            stat_response.st_mode = 32832  # 0o100100 = 0o100 + 0o100000

            self.assertTrue(
                check_file_permission(config, "test/test", False, True, False)
            )
            self.assertEqual(mock.call_count, 4)
            self.assertListEqual(
                mock.call_args_list,
                [
                    call("test/test"),
                    call("test"),
                    call("test/test"),
                    call("test/test"),
                ],
            )
            mock2.assert_called_once()

            self.assertFalse(
                check_file_permission(config, "test/test", False, False, False)
            )

            stat_response.st_mode = 0o100200
            self.assertFalse(
                check_file_permission(config, "test/test", False, False, False)
            )

            stat_response.st_mode = 0o040777
            self.assertFalse(
                check_file_permission(config, "test", False, False, False)
            )

            stat_response.st_mode = 0o100411
            self.assertFalse(
                check_file_permission(config, "test", False, False, False)
            )

            stat_response.st_mode = 0o100444
            self.assertFalse(
                check_file_permission(config, "test", False, False, False)
            )

            stat_response.st_mode = 0o100422
            self.assertFalse(
                check_file_permission(config, "test", False, False, False)
            )

            stat_response.st_mode = 32832
            stat_response.st_uid = 1
            self.assertFalse(
                check_file_permission(config, "test/test", False, True, False)
            )

        WebScripts.utils.getpwuid = getpwuid
        WebScripts.utils.isfile = isfile
        WebScripts.utils.user = user


if __name__ == "__main__":
    main()
