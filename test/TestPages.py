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

from unittest.mock import MagicMock, patch, Mock, call
from subprocess import TimeoutExpired
from unittest import TestCase, main
from subprocess import PIPE
from html import unescape
from json import loads
from time import time
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
    Blacklist,
    anti_XSS,
    Process,
    Script,
    Pages,
    Web,
    Api,
)

from WebScripts import Pages as Module
import WebScripts.Pages as Module
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
        self.assertIsNone(anti_XSS(None))

        self.assertEqual(8, anti_XSS(8))

        values = [value, value]
        tests = anti_XSS(values)
        self.assertIsNot(values, test)
        self.assertNotEqual(values, test)

        values = {value, value}

        with self.assertRaises(NotImplementedError):
            tests = anti_XSS(values)

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
            WebScripts.utils, "getpreferredencoding", return_value=None
        ) as m1, patch.object(
            WebScripts.utils, "device_encoding", return_value=None
        ) as m2:
            self.assertEqual("\u2588", decode_output(b"\xe2\x96\x88"))
            self.assertEqual("\xff\xfe\xef", decode_output(b"\xff\xfe\xef"))
            self.assertEqual("€", decode_output(b"\x80"))


class TestProcess(TestCase):
    def setUp(self):
        popen = self.popen = Mock()
        process = self.process = Process(
            popen, Mock(timeout=10), Mock(), Mock()
        )
        process.timer.cancel()
        Pages.processes.clear()

    def test_get_line(self):
        self.process.key = 0
        Pages.processes[0] = 0
        out, error, code = self.process.get_line()

        self.assertIs(
            error._mock_new_parent._mock_new_parent._mock_new_parent,
            self.popen,
        )
        self.assertIs(
            out._mock_new_parent._mock_new_parent._mock_new_parent, self.popen
        )
        self.assertEqual(code, "No errors")
        self.assertDictEqual(Pages.processes, {})

        self.process.process.poll = lambda: None
        self.process.stop_max_time = time() + 100

        out, error, code = self.process.get_line()

        self.assertEqual(error, b"")
        self.assertEqual(code, "")
        self.assertIs(
            out._mock_new_parent._mock_new_parent._mock_new_parent, self.popen
        )

        self.process.timeout = None

        out, error, code = self.process.get_line()

        self.assertEqual(error, b"")
        self.assertEqual(code, "")
        self.assertIs(
            out._mock_new_parent._mock_new_parent._mock_new_parent, self.popen
        )

        self.process.timeout = 0
        self.process.stop_max_time = 0
        Pages.processes[0] = 0

        self.process.process.kill.assert_not_called()
        out, error, code = self.process.get_line(True)

        self.assertDictEqual(Pages.processes, {})
        self.process.process.kill.assert_called_once_with()

        self.assertEqual(code, "TimeoutError")
        self.assertIs(
            out._mock_new_parent._mock_new_parent._mock_new_parent, self.popen
        )
        self.assertIs(
            error._mock_new_parent._mock_new_parent._mock_new_parent,
            self.popen,
        )
        self.assertEqual(self.process.error, "TimeoutError")

        Pages.processes[0] = 0

        out, error, code = self.process.get_line(False)

        self.assertDictEqual(Pages.processes, {0: 0})
        self.process.process.kill.assert_has_calls((), ())

        self.assertEqual(code, "TimeoutError")
        self.assertIs(b"", out)
        self.assertIs(b"", error)
        self.assertEqual(self.process.error, "TimeoutError")
        self.process.timer.cancel()

    def test_send_inputs(self):
        self.process.send_inputs(["test", "test2"])
        self.process.process.stdin.write.assert_has_calls(
            [call(b"test\n"), call(b"test2\n")]
        )
        self.process.process.stdin.close.assert_called_once_with()


class TestScript(TestCase):
    def test_get(self):
        Pages.processes.clear()
        code, headers, data = Script.get(
            Mock(), Mock(), Mock(), Mock(), 0, Mock(), Mock(), Mock()
        )
        self.assertEqual("404", code)
        self.assertEqual(b"", data)
        self.assertDictEqual({}, headers)

        Pages.processes[0] = Mock()
        code, headers, data = Script.get(
            Mock(), Mock(), Mock(), Mock(), 0, Mock(), Mock(), Mock()
        )
        self.assertEqual("403", code)
        self.assertEqual(b"", data)
        self.assertDictEqual({}, headers)

        Pages.processes[0] = Mock(
            user=Mock(id=0),
            get_line=lambda: (b"", b"", "No Error"),
            process=Mock(returncode=None),
            script=Mock(content_type="html", stderr_content_type="text"),
        )
        code, headers, data = Script.get(
            Mock(), Mock(), Mock(id=0), Mock(), 0, Mock(), Mock(), Mock()
        )
        self.assertEqual("200 OK", code)
        self.assertDictEqual(
            loads(data),
            {
                "stdout": "",
                "stderr": "",
                "code": None,
                "Content-Type": "html",
                "Stderr-Content-Type": "text",
                "error": "No Error",
                "key": 0,
            },
        )
        self.assertDictEqual(
            {"Content-Type": "application/json; charset=utf-8"}, headers
        )


class TestApi(TestCase):
    def setUp(self):
        self.api = Api()

    def test___call__(self):
        server = Mock(
            configuration=Mock(auth_script="test.go", active_auth=True)
        )

        Pages.scripts = {}
        Pages.scripts["test.go"] = Mock(
            get_JSON_API=lambda: {"script": "auth"}
        )
        Pages.scripts["other.sh"] = Mock(
            get_JSON_API=lambda: {"script": "test"}
        )

        with patch.object(Module, "check_right", return_value=False):
            code, headers, data = self.api(
                Mock(), Mock(), server, Mock(), Mock(), Mock(), Mock()
            )

        self.assertEqual(code, "200 OK")
        self.assertDictEqual(
            headers, {"Content-Type": "application/json; charset=utf-8"}
        )
        self.assertDictEqual(
            loads(data),
            {
                "/auth/": {
                    "script": "auth",
                    "name": "/auth/",
                    "category": "Authentication",
                }
            },
        )

        server = Mock(
            configuration=Mock(auth_script="test.go", active_auth=False)
        )

        server.configuration.accept_unknow_user = False
        user = Mock(id=1)

        code, headers, data = self.api(
            Mock(), user, server, Mock(), Mock(), Mock(), Mock()
        )

        self.assertEqual(code, "200 OK")
        self.assertDictEqual(
            headers, {"Content-Type": "application/json; charset=utf-8"}
        )
        self.assertDictEqual(loads(data), {})

        server = Mock(configuration=Mock(auth_script=None, active_auth=True))

        server.configuration.accept_unknow_user = True
        server.configuration.accept_unauthenticated_user = False
        user.id = 0

        code, headers, data = self.api(
            Mock(), user, server, Mock(), Mock(), Mock(), Mock()
        )

        self.assertEqual(code, "200 OK")
        self.assertDictEqual(
            headers, {"Content-Type": "application/json; charset=utf-8"}
        )
        self.assertDictEqual(loads(data), {})

        server = Mock(
            configuration=Mock(auth_script="test.go", active_auth=False)
        )
        user.id = 1000

        with patch.object(Module, "check_right", return_value=True):
            code, headers, data = self.api(
                Mock(), user, server, Mock(), Mock(), Mock(), Mock()
            )

        self.assertEqual(code, "200 OK")
        self.assertDictEqual(
            headers, {"Content-Type": "application/json; charset=utf-8"}
        )
        self.assertDictEqual(loads(data), {"other.sh": {"script": "test"}})

        Pages.scripts = {}

    def test_scripts(self):
        server = Mock(configuration=Mock(auth_script="test.go"))

        code, headers, data = self.api.scripts(
            Mock(), Mock(), server, "test.go", Mock(), Mock()
        )

        self.assertEqual(b"", data)
        self.assertEqual("404", code)
        self.assertDictEqual({}, headers)

        user = Mock(check_csrf=True)
        server.configuration.csrf_max_time = 0

        with patch.object(
            Module.TokenCSRF, "check_csrf", return_value=False
        ) as mock:
            code, headers, data = self.api.scripts(
                Mock(), user, server, "other.sh", Mock(), Mock(), "token"
            )

        self.assertEqual(b"", data)
        self.assertEqual("403", code)
        self.assertDictEqual({}, headers)

        mock.assert_called_once_with(user, "token", 0)

        user.check_csrf = False

        with patch.object(
            Module,
            "execute_scripts",
            return_value=(None, b"error", None, None, None),
        ) as mock:
            code, headers, data = self.api.scripts(
                Mock(), user, server, "other.sh", Mock(), Mock(), "token"
            )

        self.assertEqual(b"", data)
        self.assertEqual("error", code)
        self.assertDictEqual({}, headers)

        Pages.scripts["other.sh"] = Mock(
            content_type="html", stderr_content_type="text"
        )
        user.check_csrf = True

        with patch.object(
            Module,
            "execute_scripts",
            return_value=(b"result", b"error", "key", 0, "TimeoutError"),
        ) as mock, patch.object(
            Module.TokenCSRF, "check_csrf", return_value=True
        ), patch.object(
            Module.TokenCSRF, "build_token", return_value="token"
        ):
            code, headers, data = self.api.scripts(
                Mock(), user, server, "other.sh", Mock(), Mock(), "token"
            )

        self.assertDictEqual(
            loads(data),
            {
                "stdout": "result",
                "stderr": "error",
                "code": 0,
                "Content-Type": "html",
                "Stderr-Content-Type": "text",
                "error": "TimeoutError",
                "key": "key",
                "csrf": "token",
            },
        )
        self.assertEqual("200 OK", code)
        self.assertDictEqual(
            {"Content-Type": "application/json; charset=utf-8"}, headers
        )

        Pages.scripts.clear()


class TestWeb(TestCase):
    def setUp(self):
        self.web = Web()

    def test___call__(self):
        Module.CallableFile.template_index = "test %(header)s %(footer)s"
        Module.CallableFile.template_footer = "footer"
        Module.CallableFile.template_header = "header"

        code, headers, data = self.web(*[Mock()] * 7)

        self.assertEqual(code, "200 OK")
        self.assertEqual(
            headers,
            {
                "Content-Security-Policy": (
                    "default-src 'self'; navigate-to 'self'; worker-src 'none'"
                    "; style-src-elem 'self'; style-src-attr 'none'; style-src"
                    " 'self'; script-src-attr 'none'; object-src 'none'; "
                    "media-src 'none'; manifest-src 'none'; frame-ancestors "
                    "'none'; connect-src 'self'; font-src 'none'; img-src "
                    "'self'; base-uri 'none'; child-src 'none'; form-action "
                    "'none'; script-src 'self' 'require-trusted-types-for'"
                )
            },
        )
        self.assertEqual(data, "test header footer")

    def test_doc(self):
        Pages.scripts = {}

        code, headers, data = self.web.doc(
            Mock(), Mock(), Mock(), "test.go", Mock(), Mock(), Mock()
        )

        self.assertEqual(code, "404")
        self.assertDictEqual(headers, {})
        self.assertEqual(data, b"")

        user = Mock()
        script = Pages.scripts["test.go"] = Mock(
            command_generate_documentation="%(test)s",
            get_dict=lambda *x: {"test": "test"},
            documentation_file="test.html",
            documentation_content_type="html",
        )

        with patch.object(
            Module,
            "check_right",
            return_value=False,
        ) as mock:
            code, headers, data = self.web.doc(
                Mock(), user, Mock(), "test.go", Mock(), Mock(), Mock()
            )

        mock.assert_called_once_with(user, script)

        self.assertEqual(code, "403")
        self.assertDictEqual(headers, {})
        self.assertEqual(data, b"")

        server = Mock()
        env = Mock()

        with patch.object(
            Module,
            "check_right",
            return_value=True,
        ) as rigth, patch.object(
            Module,
            "Popen",
            return_value=Mock(),
        ) as popen, patch.object(
            Module, "get_environ", return_value={"env": "env"}
        ) as getenv, patch.object(
            Module.ScriptConfig,
            "get_docfile_from_configuration",
            return_value=None,
        ) as get_docfile, patch.object(
            Module,
            "get_real_path",
            return_value="file.txt",
        ) as get_file:
            code, headers, data = self.web.doc(
                env, user, server, "test.go", Mock(), Mock(), Mock()
            )

        rigth.assert_called_once_with(user, script)
        popen.assert_called_once_with("test", env={"env": "env"}, shell=True)
        get_docfile.assert_called_once_with(server.configuration, "test.go")
        getenv.assert_called_once_with(env, user, script)
        get_file.assert_called_once_with("test.html")

        self.assertEqual(code, "404")
        self.assertDictEqual(headers, {})
        self.assertEqual(data, b"")

        script.command_generate_documentation = None
        script.get_dict = None

        with patch.object(
            Module,
            "check_right",
            return_value=True,
        ) as rigth, patch.object(
            Module.path,
            "isfile",
            return_value=True,
        ) as isfile, patch.object(
            Module,
            "get_file_content",
            return_value=b"data",
        ) as getcontent, patch.object(
            Module,
            "get_real_path",
            return_value="file.txt",
        ) as get_file:
            code, headers, data = self.web.doc(
                env, user, server, "test.go", Mock(), Mock(), Mock()
            )

        rigth.assert_called_once_with(user, script)
        isfile.assert_called_once_with("file.txt")
        getcontent.assert_called_once_with("file.txt", as_iterator=True)
        get_file.assert_called_once_with("test.html")

        self.assertEqual(code, "200 OK")
        self.assertDictEqual(headers, {"Content-Type": "html; charset=utf-8"})
        self.assertEqual(data, b"data")

        with patch.object(
            Module,
            "check_right",
            return_value=True,
        ) as rigth, patch.object(
            Module.ScriptConfig,
            "get_docfile_from_configuration",
            return_value="file.txt",
        ) as get_docfile, patch.object(
            Module,
            "get_file_content",
            return_value=b"data",
        ) as getcontent, patch.object(
            Module,
            "get_real_path",
            return_value="file.txt",
        ) as get_file:
            code, headers, data = self.web.doc(
                env, user, server, "test.go", Mock(), Mock(), Mock()
            )

        rigth.assert_called_once_with(user, script)
        get_docfile.assert_called_once_with(server.configuration, "test.go")
        getcontent.assert_called_once_with("file.txt", as_iterator=True)
        get_file.assert_called_once_with("test.html")

        self.assertEqual(code, "200 OK")
        self.assertDictEqual(headers, {"Content-Type": "html; charset=utf-8"})
        self.assertEqual(data, b"data")

    def test_auth(self):
        server = Mock(
            configuration=Mock(active_auth=True, auth_script="test.go")
        )
        function = Mock()
        user = Mock()

        with patch.object(
            Module, "CallableFile", return_value=function
        ) as file:
            self.web.auth(Mock(), user, server, Mock(), Mock(), Mock())

        function.assert_called_once_with(user)
        file.assert_called_once_with("script", "test.go", "/auth/")

        server.configuration.active_auth = False

        code, headers, data = self.web.auth(
            Mock(), user, server, Mock(), Mock(), Mock()
        )

        self.assertEqual(data, b"")
        self.assertEqual(code, "403")
        self.assertDictEqual(headers, {})

    def test_scripts(self):
        server = Mock(
            configuration=Mock(active_auth=True, auth_script="test.go")
        )
        code, headers, data = self.web.scripts(
            Mock(), Mock(), server, "test.go", Mock(), Mock()
        )

        self.assertEqual(code, "404")
        self.assertDictEqual({}, headers)
        self.assertEqual(data, b"")

        Pages.scripts = {}

        code, headers, data = self.web.scripts(
            Mock(), Mock(), server, "other.sh", Mock(), Mock()
        )

        self.assertEqual(code, "404")
        self.assertDictEqual({}, headers)
        self.assertEqual(data, b"")

        Pages.scripts["other.sh"] = "other"

        with patch.object(
            Module, "check_right", return_value=True
        ), patch.object(Module, "CallableFile", return_value=None):
            code, headers, data = self.web.scripts(
                Mock(), Mock(), server, "other.sh", Mock(), Mock()
            )

        self.assertEqual(code, "404")
        self.assertDictEqual({}, headers)
        self.assertEqual(data, b"")

        with patch.object(Module, "check_right", return_value=False):
            code, headers, data = self.web.scripts(
                Mock(), Mock(), server, "other.sh", Mock(), Mock()
            )

        self.assertEqual(code, "403")
        self.assertDictEqual({}, headers)
        self.assertEqual(data, b"")

        with patch.object(
            Module, "check_right", return_value=True
        ), patch.object(
            Module, "CallableFile", return_value=Mock(return_value="test")
        ):
            self.assertEqual(
                "test",
                self.web.scripts(
                    Mock(), Mock(), server, "other.sh", Mock(), Mock()
                ),
            )


class TestPages(TestCase):
    def setUp(self):
        self.pages = Pages()

    def test___call__(self):
        code, headers, data = self.pages(
            Mock(), Mock(), Mock(), Mock(), Mock(), Mock()
        )

        self.assertEqual("301 Moved Permanently", code)
        self.assertDictEqual({"Location": "/web/"}, headers)
        self.assertEqual(
            (
                b"<!-- To use API go to this URL: /api/ --><html><body><h1>"
                b'Index page is /web/</h1><a href="/web/">Please click here'
                b'</a><script>window.location="/web/"</script></html>'
            ),
            data,
        )

    def test_auth(self):
        Pages.js_paths = {}
        code, headers, data = self.pages.js(
            Mock(), Mock(), Mock(), "test", Mock(), Mock()
        )

        self.assertEqual(b"", data)
        self.assertEqual("404", code)
        self.assertDictEqual({}, headers)

        Pages.js_paths["test"] = Mock(return_value="whynot")
        self.assertEqual(
            "whynot",
            self.pages.js(Mock(), Mock(), Mock(), "test", Mock(), Mock()),
        )

    def test_static(self):
        Pages.statics_paths = {}
        code, headers, data = self.pages.static(
            Mock(), Mock(), Mock(), "test", Mock(), Mock()
        )

        self.assertEqual(b"", data)
        self.assertEqual("404", code)
        self.assertDictEqual({}, headers)

        Pages.statics_paths["test"] = Mock(return_value="whynot")
        self.assertEqual(
            "whynot",
            self.pages.static(Mock(), Mock(), Mock(), "test", Mock(), Mock()),
        )

    def test_js(self):
        Pages.js_paths = {}
        code, headers, data = self.pages.js(
            Mock(), Mock(), Mock(), "test", Mock(), Mock()
        )

        self.assertEqual(b"", data)
        self.assertEqual("404", code)
        self.assertDictEqual({}, headers)

        Pages.js_paths["test"] = Mock(return_value="whynot")
        self.assertEqual(
            "whynot",
            self.pages.js(Mock(), Mock(), Mock(), "test", Mock(), Mock()),
        )

    def test_auth(self):
        env = {"REMOTE_IP": "0.0.0.0"}
        server = Mock(
            configuration=Mock(
                active_auth=None, auth_script="test.go", session_max_time=0
            )
        )
        user = Mock()
        script = "other.sh"
        command = ["--username", "test"]
        inputs = Mock()

        self.pages.auth(env, user, server, script, command, inputs)

        server.configuration.active_auth = "test.go"

        with patch.object(
            Module,
            "execute_scripts",
            return_value=(b"out", b"err", "key", 0, "TimeoutError"),
        ) as mock:
            code, headers, data = self.pages.auth(
                env, user, server, script, command, inputs
            )
            self.assertEqual(b"", data)
            self.assertEqual(code, "err")
            self.assertDictEqual({}, headers)
            mock.assert_called_once_with(
                "test.go", user, env, command, inputs, is_auth=True
            )

        with patch.object(
            Module,
            "execute_scripts",
            return_value=(b"out", b"error", "key", 1, "TimeoutError"),
        ) as mock:
            code, headers, data = self.pages.auth(
                env, user, server, script, command, inputs
            )
            self.assertEqual(b"", data)
            self.assertEqual(code, "500")
            self.assertDictEqual({}, headers)
            mock.assert_called_once_with(
                "test.go", user, env, command, inputs, is_auth=True
            )

        with patch.object(
            Module,
            "execute_scripts",
            return_value=(None, b"error", "key", 0, "TimeoutError"),
        ) as mock:
            code, headers, data = self.pages.auth(
                env, user, server, script, command, inputs
            )
            self.assertEqual(b"", data)
            self.assertEqual(code, "500")
            self.assertDictEqual({}, headers)
            mock.assert_called_once_with(
                "test.go", user, env, command, inputs, is_auth=True
            )

        with patch.object(
            Module,
            "execute_scripts",
            return_value=(b"", b"error", "key", 0, "TimeoutError"),
        ) as mock:
            code, headers, data = self.pages.auth(
                env, user, server, script, command, inputs
            )
            self.assertEqual(b"", data)
            self.assertEqual(code, "500")
            self.assertDictEqual({}, headers)
            mock.assert_called_once_with(
                "test.go", user, env, command, inputs, is_auth=True
            )

        user_session = Mock(id=1)
        with patch.object(
            Module,
            "execute_scripts",
            return_value=(
                b'{"data":"data"}',
                b"",
                "key",
                0,
                "TimeoutError",
            ),
        ) as mock, patch.object(
            Module.User, "default_build", return_value=user_session
        ) as getuser, patch.object(
            Module.Session, "build_session", return_value="cookie"
        ) as session:
            code, headers, data = self.pages.auth(
                env, user, server, script, command, inputs
            )
            self.assertIsInstance(
                self.pages.ip_blacklist.get("0.0.0.0"), Blacklist
            )
            self.assertIsInstance(
                self.pages.user_blacklist.get("test"), Blacklist
            )
            self.assertEqual(b"", data)
            self.assertEqual(code, "302 Found")
            self.assertDictEqual(
                {
                    "Set-Cookie": (
                        "SessionID=cookie; Path=/; SameSite=Strict;"
                        " Max-Age=0; Secure; HttpOnly"
                    ),
                },
                headers,
            )

            getuser.assert_called_once_with(data="data")
            session.assert_called_once_with(user_session, "0.0.0.0", Pages)
            mock.assert_called_once_with(
                "test.go", user, env, command, inputs, is_auth=True
            )

    def test_reload(self):
        self.assertIsNone(self.pages.reload(*[Mock()] * 6))


if __name__ == "__main__":
    main()
