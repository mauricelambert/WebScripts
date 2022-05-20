#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file tests the Pages.py file
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

"""
This file tests the Pages.py file
"""

from unittest.mock import MagicMock, patch, Mock
from subprocess import TimeoutExpired
from unittest import TestCase, main
from subprocess import PIPE
from html import unescape
from os import path
import locale
import sys

WebScripts_path = path.join(path.dirname(__file__), "..")

if WebScripts_path not in sys.path:
    sys.path.insert(0, WebScripts_path)

from WebScripts.Pages import (
    check_categories_scripts_access,
    execute_scripts,
    execution_logs,
    decode_output,
    start_process,
    check_right,
    get_environ,
    anti_XSS,
    Process,
    Pages,
)

from WebScripts import Pages as Module
import WebScripts.utils


class TestFunctions(TestCase):
    def test_execute_scripts(self):
        Pages.scripts = {}
        out, err, key, code, error = execute_scripts(
            "test", None, None, None, None
        )
        self.assertIsNone(out)
        self.assertIsNone(key)
        self.assertEqual(b"404", err)
        self.assertEqual(-1, code)
        self.assertEqual("Not Found", error)

        Pages.scripts = {"test": "test2"}

        with patch.object(
            Module,
            "check_right",
            return_value=False,
        ) as mock_method:

            out, err, key, code, error = execute_scripts(
                "test", "User", None, None, None
            )

            mock_method.assert_called_once_with("User", "test2")

        self.assertIsNone(out)
        self.assertIsNone(key)
        self.assertEqual(b"403", err)
        self.assertEqual(-1, code)
        self.assertEqual("Forbidden", error)

        script = Mock(path="path", launcher=None)
        Pages.scripts = {"test": script}

        with patch.object(
            Module,
            "get_environ",
            return_value={"test": "test1"},
        ) as m_get_environ, patch.object(
            Module, "Popen", return_value="process"
        ) as m_popen, patch.object(
            Module,
            "start_process",
            return_value=("stdout", "stderr", "key", "error", "code"),
        ) as m_start_process, patch.object(
            Module, "execution_logs"
        ) as m_logs:

            out, err, key, code, error = execute_scripts(
                "test",
                "User",
                {"test": "test"},
                ["abc"],
                ["def"],
                True,
            )

            m_get_environ.assert_called_once_with(
                {"test": "test"}, "User", script
            )
            m_popen.assert_called_once_with(
                ["path", "abc"],
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE,
                shell=False,
                env={"test": "test1"},
            )
            m_start_process.assert_called_once_with(
                script, "process", "User", ["def"]
            )
            m_logs.assert_called_once_with(script, "User", "process", "stderr")

        self.assertEqual(out, "stdout")
        self.assertEqual(key, "key")
        self.assertEqual("stderr", err)
        self.assertEqual("code", code)
        self.assertEqual("error", error)

        script = Mock(path="path", launcher="launcher")
        Pages.scripts = {"test": script}

        with patch.object(
            Module,
            "get_environ",
            return_value={"test": "test1"},
        ) as m_get_environ, patch.object(
            Module, "Popen", return_value="process"
        ) as m_popen, patch.object(
            Module,
            "start_process",
            return_value=("stdout", "stderr", "key", "error", "code"),
        ) as m_start_process, patch.object(
            Module, "execution_logs"
        ) as m_logs:

            out, err, key, code, error = execute_scripts(
                "test",
                "User",
                {"test": "test"},
                ["abc"],
                ["def"],
                True,
            )

            m_get_environ.assert_called_once_with(
                {"test": "test"}, "User", script
            )
            m_popen.assert_called_once_with(
                ["launcher", "path", "abc"],
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE,
                shell=False,
                env={"test": "test1"},
            )
            m_start_process.assert_called_once_with(
                script, "process", "User", ["def"]
            )
            m_logs.assert_called_once_with(script, "User", "process", "stderr")

        self.assertEqual(out, "stdout")
        self.assertEqual(key, "key")
        self.assertEqual("stderr", err)
        self.assertEqual("code", code)
        self.assertEqual("error", error)

    def test_start_process(self):
        script = Mock(print_real_time=True)
        proc = Mock()

        with patch.object(Module, "Process", return_value=proc) as Process:
            out, err, key, error, code = start_process(
                script, "process", "user", "inputs"
            )
            Process.assert_called_once_with("process", script, "user", key)

        self.assertIsNone(error)
        self.assertIsNone(code)
        self.assertEqual(out, b"")
        self.assertEqual(err, b"")
        self.assertIsInstance(key, str)
        self.assertEqual(len(key), 56)  # 40 bytes in base64
        self.assertIs(proc, Pages.processes[key])

        script = Mock(print_real_time=False, timeout=0)
        com = Mock(return_value=("stdout", "stderr"))
        kill = Mock()
        proc = Mock(communicate=com, returncode=0, kill=kill)
        out, err, key, error, code = start_process(
            script, proc, "user", ["inputs"]
        )

        self.assertIsNone(key)
        self.assertEqual(code, 0)
        self.assertEqual(out, "stdout")
        self.assertEqual(err, "stderr")
        self.assertEqual(error, "No errors")
        com.assert_called_once_with(input=b"inputs", timeout=0)
        kill.assert_not_called()

        def a(input=None, timeout=None):
            if sys.exc_info() == (None, None, None):
                raise TimeoutExpired("cmd", 5)
            else:
                return "stdout", "stderr"

        proc = Mock(communicate=a, returncode=1, kill=kill)
        out, err, key, error, code = start_process(
            script, proc, Mock(), "inputs"
        )

        self.assertIsNone(key)
        self.assertEqual(code, 1)
        self.assertEqual(out, "stdout")
        self.assertEqual(err, "stderr")
        self.assertEqual(error, "TimeoutError")
        kill.assert_called_once_with()

    def test_anti_XSS(self):
        value = "<string length=\"8\" name='str' & other>"
        test = anti_XSS(value)
        self.assertNotEqual(value, test)
        self.assertNotIn("<", test)
        self.assertNotIn(">", test)
        self.assertNotIn('"', test)
        self.assertNotIn("'", test)
        self.assertEqual(value, unescape(test))

        self.assertEqual(8, anti_XSS(8))

        values = [value, value]
        tests = anti_XSS(values)
        self.assertIsNot(values, test)
        self.assertNotEqual(values, test)

        for test in tests:
            self.assertNotEqual(value, test)
            self.assertNotIn("<", test)
            self.assertNotIn(">", test)
            self.assertNotIn('"', test)
            self.assertNotIn("'", test)
            self.assertEqual(value, unescape(test))

        values = {"attr": value}
        tests = anti_XSS(values)
        self.assertIsNot(values, tests)
        self.assertNotEqual(values, tests)
        self.assertNotEqual(value, tests["attr"])
        self.assertNotIn("<", tests["attr"])
        self.assertNotIn(">", tests["attr"])
        self.assertNotIn('"', tests["attr"])
        self.assertNotIn("'", tests["attr"])
        self.assertEqual(value, unescape(tests["attr"]))

    def test_execution_logs(self):
        execution_logs(
            Mock(no_password=True, name="script"),
            Mock(name="user"),
            Mock(returncode=1, args=["arg1"]),
            b"",
        )
        execution_logs(
            Mock(no_password=False, name="script"),
            Mock(name="user"),
            Mock(returncode=0, args=["arg1"]),
            b"",
        )
        execution_logs(
            Mock(no_password=True, name="script"),
            Mock(name="user"),
            Mock(returncode=0, args=["arg1"]),
            b"stderr",
        )
        # coverage only

    def test_get_environ(self):
        env = {
            "wsgi.run_once": "abc",
            "wsgi.input": "test",
            "wsgi.errors": "abc",
            "wsgi.file_wrapper": "test",
            "wsgi.version": (0, 1, 2),
            "int": 10,
        }
        new_env = get_environ(
            env,
            Mock(get_dict=lambda: "user"),
            Mock(get_JSON_API=lambda: "script"),
        )

        self.assertIsNot(env, new_env)
        self.assertNotEqual(env, new_env)

        self.assertEqual(new_env["USER"], '"user"')
        self.assertEqual(new_env["SCRIPT_CONFIG"], '"script"')

        self.assertEqual(new_env["wsgi.version"], "0.1.2")
        self.assertEqual(new_env["int"], "10")
        self.assertNotIn("wsgi.run_once", new_env)
        self.assertNotIn("wsgi.input", new_env)
        self.assertNotIn("wsgi.errors", new_env)
        self.assertNotIn("wsgi.file_wrapper", new_env)

    def test_check_right(self):
        user = Mock(groups=[1000])
        configuration = Mock(
            minimum_access=None, access_users=None, access_groups=[1000]
        )

        with patch.object(
            Module, "check_categories_scripts_access", return_value=True
        ) as method:
            self.assertTrue(check_right(user, configuration))
            method.assert_called_once_with(user, configuration)

        user = Mock(id=1000)
        configuration = Mock(
            minimum_access=None, access_users=[1000], access_groups=None
        )

        with patch.object(
            Module, "check_categories_scripts_access", return_value=True
        ) as method:
            self.assertTrue(check_right(user, configuration))
            method.assert_called_once_with(user, configuration)

        user = Mock(groups=[1000])
        configuration = Mock(
            access_users=None, minimum_access=1000, access_groups=None
        )

        with patch.object(
            Module, "check_categories_scripts_access", return_value=True
        ) as method:
            self.assertTrue(check_right(user, configuration))
            method.assert_called_once_with(user, configuration)

        user = Mock()
        configuration = Mock(
            minimum_access=None, access_users=None, access_groups=None
        )

        with patch.object(
            Module, "check_categories_scripts_access", return_value=True
        ) as method:
            self.assertTrue(check_right(user, configuration))
            method.assert_called_once_with(user, configuration)

        user = Mock(groups=[999])
        configuration = Mock(
            minimum_access=1000, access_users=None, access_groups=None
        )
        self.assertFalse(check_right(user, configuration))

    def test_check_categories_scripts_access(self):
        class MyObjectTest:
            pass

        user = Mock(
            categories=["test", "test_*"], scripts=["scriptest", "scriptest_*"]
        )
        configuration = Mock(category="test")
        self.assertTrue(check_categories_scripts_access(user, configuration))

        configuration = Mock(category="test_test")
        self.assertTrue(check_categories_scripts_access(user, configuration))

        configuration = MyObjectTest()
        configuration.category = "testfalse"
        configuration.name = "scriptest"
        # configuration = Mock(category="testfalse", name="scriptest")
        self.assertTrue(check_categories_scripts_access(user, configuration))

        configuration.name = "scriptest_test"
        # configuration = Mock(category="testfalse", name="scriptest_test")
        self.assertTrue(check_categories_scripts_access(user, configuration))

        configuration.name = "scriptestfalse"
        # configuration = Mock(category="testfalse", name="scriptestfalse")
        self.assertFalse(check_categories_scripts_access(user, configuration))

    def test_decode_output(self):
        with patch.object(
            WebScripts.utils.locale, "getpreferredencoding", return_value=None
        ) as m1, patch.object(
            WebScripts.utils, "device_encoding", return_value=None
        ) as m2:
            self.assertEqual("\u2588", decode_output(b"\xe2\x96\x88"))
            self.assertEqual("\xff\xfe\xef", decode_output(b"\xff\xfe\xef"))
            self.assertEqual("€", decode_output(b"\x80"))


if __name__ == "__main__":
    main()
