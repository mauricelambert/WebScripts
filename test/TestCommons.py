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

"""This file test the commons.py file"""

from unittest.mock import Mock, patch
from unittest import TestCase, main
from time import sleep, time
from os import path

import logging.config
import logging
import json
import sys
import os

sys.path = [path.join(path.dirname(__file__), ".."), *sys.path]

from WebScripts.commons import (
    Argument,
    WebScriptsArgumentError,
    ScriptConfig,
    WebScriptsConfigurationError,
    WebScriptsSecurityError,
    DefaultNamespace,
    CallableFile,
    Blacklist,
    TokenCSRF,
    Session,
)
import WebScripts.commons


def disable_logs():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})
    logging.disable()


disable_logs()


class TestArgument(TestCase):
    def test_get_command(self):
        arguments = Argument.get_command("--test", {"value": True})
        self.assertEqual(len(arguments), 1)
        self.assertDictEqual({"value": "--test", "input": False}, arguments[0])

        arguments = Argument.get_command("test", {"value": 8, "input": True})
        self.assertEqual(len(arguments), 1)
        self.assertDictEqual({"value": "8", "input": True}, arguments[0])

        arguments = Argument.get_command("test", {"value": "8", "input": True})
        self.assertEqual(len(arguments), 1)
        self.assertDictEqual({"value": "8", "input": True}, arguments[0])

        arguments = Argument.get_command(
            "-t", {"value": ["", 8, "", "test", ""], "input": True}
        )
        self.assertEqual(len(arguments), 3)
        self.assertDictEqual({"value": "-t", "input": False}, arguments[0])
        self.assertDictEqual({"value": "8", "input": False}, arguments[1])
        self.assertDictEqual({"value": "test", "input": False}, arguments[2])

        self.assertListEqual([], Argument.get_command("-t", {"value": None}))
        self.assertListEqual([], Argument.get_command("-t", {"value": ""}))
        self.assertListEqual([], Argument.get_command("-t", {"value": False}))
        self.assertListEqual(
            [], Argument.get_command("-t", {"value": ["", "", ""]})
        )

        with self.assertRaises(WebScriptsArgumentError):
            Argument.get_command("-t", {"value": {"1"}})


class TestScriptConfig(TestCase):
    def test_build_args(self):
        configuration = {
            "args": [{"name": "test", "javascript_section": "test"}],
            "test": {"abc": "test"},
        }

        config = ScriptConfig()
        config.update(**configuration)
        config.build_args(configuration)

        self.assertEqual(len(config.args), 1)
        self.assertEqual(config.args[0].javascript_section, "test")
        self.assertDictEqual(
            config.args[0].javascript_attributs, {"abc": "test"}
        )

        configuration.pop("test")

        config = ScriptConfig()
        config.update(**configuration)

        with self.assertRaises(WebScriptsConfigurationError):
            config.build_args(configuration)

    def test_build_scripts_from_configuration(self):

        with open("unittests_configuration.ini", "w") as file:
            file.write("[scripts]\ntest.py=test\n\n[test]\n")

        with open("unittests_configuration.json", "w") as file:
            json.dump({"scripts": {"test.sh": "test"}, "test": {}}, file)

        configuration = DefaultNamespace()
        configuration.ini_scripts_config = ["./unittests_configuration.ini"]
        configuration.json_scripts_config = ["./unittests_configuration.json"]

        with patch.object(
            ScriptConfig, "get_scripts_from_configuration"
        ) as config_mock:
            config_mock.return_value = {}
            ScriptConfig.build_scripts_from_configuration(configuration)

        self.assertEqual(len(config_mock.mock_calls), 3)

        self.assertEqual(len(config_mock.mock_calls[0].args), 2)
        self.assertListEqual(
            config_mock.mock_calls[0].args[0].ini_scripts_config,
            ["./unittests_configuration.ini"],
        )
        self.assertListEqual(
            config_mock.mock_calls[0].args[0].json_scripts_config,
            ["./unittests_configuration.json"],
        )

        self.assertEqual(len(config_mock.mock_calls[1].args), 2)
        self.assertDictEqual(
            config_mock.mock_calls[1].args[0].scripts, {"test.py": "test"}
        )
        self.assertDictEqual(config_mock.mock_calls[1].args[0].test, {})

        self.assertEqual(len(config_mock.mock_calls[2].args), 2)
        self.assertDictEqual(
            config_mock.mock_calls[2].args[0].scripts, {"test.sh": "test"}
        )
        self.assertDictEqual(config_mock.mock_calls[2].args[0].test, {})

        os.remove("unittests_configuration.ini")
        os.remove("unittests_configuration.json")

    def test_get_scripts_from_configuration(self):
        configuration = DefaultNamespace()
        configuration.scripts = {"test.py": "test"}

        with self.assertRaises(WebScriptsConfigurationError):
            ScriptConfig.get_scripts_from_configuration(configuration, None)

        configuration.test = {}

        with patch.object(ScriptConfig, "get_script_path") as mock_config_path:
            mock_config_path.return_value = "/fake/path/test.py"
            script_configs = ScriptConfig.get_scripts_from_configuration(
                configuration, configuration
            )

        self.assertFalse(script_configs["test.py"].path_is_defined)
        self.assertEqual(script_configs["test.py"].dirname, "/fake/path")
        self.assertEqual(script_configs["test.py"].path, "/fake/path/test.py")
        self.assertEqual(script_configs["test.py"].name, "test.py")

        configuration = DefaultNamespace()
        configuration.scripts = {"test.py": "test"}
        configuration.test = {"path": "/fake/path/test.py"}

        with patch.object(
            WebScripts.commons, "get_real_path"
        ) as mock_real_path:
            mock_real_path.return_value = "/fake/path/test.py"
            with self.assertRaises(WebScriptsConfigurationError):
                ScriptConfig.get_scripts_from_configuration(
                    configuration, configuration
                )

        configuration.test = {"path": "test.py"}

        with open("test.py", "w") as file:
            file.write("# test")

        script_configs = ScriptConfig.get_scripts_from_configuration(
            configuration, configuration
        )
        self.assertTrue(script_configs["test.py"].path_is_defined)

        os.remove("test.py")

    def test_get_Windows_default_script_launcher(self):
        with patch.object(WebScripts.commons, "system") as mock_system:
            mock_system.return_value = "Linux"
            self.assertIsNone(
                ScriptConfig.get_Windows_default_script_launcher(None)
            )

        with patch.object(WebScripts.commons, "system") as mock_system:
            mock_system.return_value = "Windows"

            with self.assertRaises(WebScriptsSecurityError):
                ScriptConfig.get_Windows_default_script_launcher(
                    {"path": "abc.command injection", "name": ""}
                )

            with patch.object(WebScripts.commons, "Popen") as mock_process:
                mock_process.return_value = Mock(
                    returncode=1, communicate=Mock(return_value=("", ""))
                )
                self.assertIsNone(
                    ScriptConfig.get_Windows_default_script_launcher(
                        {"path": "abc.py", "name": ""}
                    )
                )

                mock_process.return_value = Mock(
                    returncode=0, communicate=Mock(return_value=("", ""))
                )
                self.assertIsNone(
                    ScriptConfig.get_Windows_default_script_launcher(
                        {"path": "abc.py", "name": ""}
                    )
                )

                mock_process.return_value = Mock(
                    returncode=0, communicate=Mock(return_value=('="abc', ""))
                )
                self.assertEqual(
                    ScriptConfig.get_Windows_default_script_launcher(
                        {"path": "abc.py", "name": ""}
                    ),
                    "abc",
                )

    def test_get_script_path(self):
        server_config = DefaultNamespace()
        server_config.scripts_path = "."
        script_config = {"name": "test.py"}

        with self.assertRaises(WebScriptsConfigurationError):
            ScriptConfig.get_script_path(server_config, script_config)

        with open("test.py", "w") as file:
            file.write("# test")

        script_path = ScriptConfig.get_script_path(
            server_config, script_config
        )
        self.assertTrue(script_path.startswith(os.getcwd()))
        self.assertTrue(script_path.endswith("test.py"))
        self.assertTrue(path.isfile(script_path))

    def test_get_documentation_from_configuration(self):
        self.assertEqual(
            ScriptConfig.get_documentation_from_configuration(
                {"documentation_file": "test"}, "test.py", ["."]
            ),
            "test",
        )
        self.assertIsNone(
            ScriptConfig.get_documentation_from_configuration(
                {}, "test_doc.py", ["."]
            )
        )

        with open("test_doc.html", "w") as file:
            file.write("<html></html>")

        self.assertEqual(
            ScriptConfig.get_documentation_from_configuration(
                {}, "test_doc.py", ["."]
            ),
            path.join(".", "test_doc.html"),
        )
        os.remove("test_doc.html")

    def test_get_arguments_from_config(self):
        self.assertListEqual(
            ScriptConfig.get_arguments_from_config(None, None), []
        )

        with self.assertRaises(WebScriptsConfigurationError):
            ScriptConfig.get_arguments_from_config("test", {})

        with self.assertRaises(WebScriptsConfigurationError):
            ScriptConfig.get_arguments_from_config(
                "test", {"test": {"arg": "arg_test"}}
            )

        args = ScriptConfig.get_arguments_from_config(
            "test", {"test": {"arg": "arg_test"}, "arg_test": {}}
        )
        self.assertEqual(len(args), 1)
        self.assertDictEqual(args[0], {"name": "arg"})

    def test_get_script_config_from_specific_file_config(self):
        self.assertEqual(
            ScriptConfig.get_script_config_from_specific_file_config({}, None),
            (None, {}),
        )

        with open("test.json", "w") as file:
            json.dump({"no_script": {"test": "test"}}, file)

        with self.assertRaises(WebScriptsConfigurationError):
            ScriptConfig.get_script_config_from_specific_file_config(
                {"configuration_file": "test.json"}, {}
            )

        with open("test.ini", "w") as file:
            file.write("[script]\ntest=test")

        configs = ScriptConfig.get_script_config_from_specific_file_config(
            {"configuration_file": "test.ini"}, {}
        )

        self.assertDictEqual(configs[0]["script"], configs[1])
        self.assertDictEqual(configs[0], {"script": {"test": "test"}})

        with open("test.json", "w") as file:
            json.dump({"script": {"test": "test"}}, file)

        configs = ScriptConfig.get_script_config_from_specific_file_config(
            {"configuration_file": "test.json"}, {}
        )

        self.assertDictEqual(configs[0]["script"], configs[1])
        self.assertDictEqual(configs[0], {"script": {"test": "test"}})

    def test_get_JSON_API(self):
        script = DefaultNamespace()
        arg = DefaultNamespace()
        arg.update(test="test")

        script.update(
            **{
                "command_generate_documentation": 1,
                "documentation_file": 1,
                "print_real_time": 1,
                "minimum_access": 1,
                "access_groups": 1,
                "access_users": 1,
                "no_password": 1,
                "launcher": 1,
                "timeout": 1,
                "dirname": 1,
                "path": 1,
                "secrets": 1,
                "args": [arg],
            }
        )

        json_api = ScriptConfig.get_JSON_API(script)
        self.assertDictEqual(json_api.get("args", {})[0], {"test": "test"})
        self.assertDictEqual(json_api, {"args": [{"test": "test"}]})

    def test_get_docfile_from_configuration(self):
        config = DefaultNamespace()
        config.documentations_path = ["."]

        with patch.object(WebScripts.commons, "iglob") as mock_glob:
            mock_glob.return_value = [
                "error.html",
                "no_test.html",
                "te.html",
                "test.html",
            ]
            self.assertEqual(
                ScriptConfig.get_docfile_from_configuration(config, "test.py"),
                "test.html",
            )


class TestCallableFile(TestCase):
    def test___call__(self):
        with patch.object(
            WebScripts.commons, "get_file_content"
        ) as mock_file_content:
            mock_file_content.return_value = b"content"

            file = CallableFile("js", "file.js", "file.js")
            code, headers, content = file(None)
            self.assertEqual(code, "200 OK")
            self.assertDictEqual(
                headers, {"Content-Type": "text/javascript; charset=utf-8"}
            )

            for headers_ref, extentions in [
                (
                    {"Content-Type": "text/html; charset=utf-8"},
                    (".html", ".htm", ".shtml", ".xhtml"),
                ),
                ({"Content-Type": "text/css; charset=utf-8"}, (".css",)),
                ({"Content-Type": "image/x-icon"}, (".ico",)),
                ({"Content-Type": "image/png"}, (".png",)),
                ({"Content-Type": "image/jpeg"}, (".jpg", ".jpeg", ".jpe")),
                ({"Content-Type": "image/gif"}, (".gif",)),
                (
                    {"Content-Type": "application/json; charset=utf-8"},
                    (".json",),
                ),
                ({"Content-Type": "text/plain; charset=utf-8"}, (".txt",)),
                (
                    {"Content-Type": "application/pdf; charset=utf-8"},
                    (".pdf",),
                ),
                ({"Content-Type": "text/csv; charset=utf-8"}, (".csv",)),
                ({"Content-Type": "image/tiff"}, (".tiff", ".tif")),
                (
                    {"Content-Type": "application/xml; charset=utf-8"},
                    (
                        ".xml",
                        ".xsd",
                        ".xslt",
                        ".tld",
                        ".dtml",
                        ".rss",
                        ".opml",
                    ),
                ),
                ({"Content-Type": "image/svg+xml"}, (".svg",)),
                (
                    {"Content-Type": "application/octet-stream"},
                    (".test", ".error", ".bin"),
                ),
            ]:
                for extention in extentions:
                    file = CallableFile(
                        "static", f"file.{extention}", f"file.{extention}"
                    )
                    code, headers, content = file(None)
                    self.assertEqual(code, "200 OK")
                    self.assertDictEqual(headers, headers_ref)

            user = DefaultNamespace()
            user.name = "test"
            user.csrf = {}

            CallableFile.template_script = (
                "%(name)s_%(user)s_%(csrf)s_%(nonce)s"
            )

            file = CallableFile("script", "file.py", "file.py")
            code, headers, content = file(user)
            self.assertEqual(code, "200 OK")
            self.assertEqual(
                headers["Content-Type"], "text/html; charset=utf-8"
            )
            self.assertRegex(
                headers["Content-Security-Policy"],
                r"default-src 'self'; form-action 'none'; frame-ancestors 'none'; script-src 'self' 'nonce-[\da-fA-F]{20}",
            )
            self.assertRegex(
                content, r"file\.py_test_[\w\d+/]+={0,2}_[\da-fA-F]{20}"
            )


class TestBlacklist(TestCase):
    def test___init__(self):
        blacklist = Blacklist(None, None)
        self.assertEqual(blacklist.counter, 1)

        configuration = DefaultNamespace()
        configuration.blacklist_time = None

        blacklist = Blacklist(configuration, blacklist)
        self.assertEqual(blacklist.counter, 1)

        configuration.blacklist_time = 0

        blacklist = Blacklist(configuration, None)
        self.assertEqual(blacklist.counter, 1)

        sleep(0.0001)
        blacklist = Blacklist(configuration, blacklist)
        self.assertEqual(blacklist.counter, 1)

        configuration.blacklist_time = 5

        blacklist = Blacklist(configuration, blacklist)
        self.assertEqual(blacklist.counter, 2)

    def test_is_blacklist(self):
        configuration = DefaultNamespace()
        configuration.auth_failures_to_blacklist = None

        blacklist = Blacklist(None, None)
        self.assertFalse(blacklist.is_blacklist(configuration))

        configuration.auth_failures_to_blacklist = 5

        blacklist = Blacklist(configuration, blacklist)
        self.assertFalse(blacklist.is_blacklist(configuration))

        blacklist = Blacklist(configuration, blacklist)
        blacklist.counter = 6
        self.assertFalse(blacklist.is_blacklist(configuration))

        configuration.blacklist_time = 0

        blacklist = Blacklist(configuration, blacklist)
        blacklist.counter = 6
        blacklist.time = 0
        self.assertFalse(blacklist.is_blacklist(configuration))

        configuration.blacklist_time = 5

        blacklist = Blacklist(configuration, blacklist)
        blacklist.counter = 6
        self.assertTrue(blacklist.is_blacklist(configuration))

    def test___str__(self):
        blacklist = Blacklist(None, None)
        self.assertRegex(
            str(blacklist),
            r"Blacklist\(counter=1, blacklist_time=\d+\.\d+(e-\d{2})?\)",
        )


class TestTokenCSRF(TestCase):
    def test_build_token(self):
        user = DefaultNamespace()
        user.csrf = {}
        token = TokenCSRF.build_token(user)
        self.assertRegex(token, r"[a-zA-Z\d+/]{64}")
        for token_ in user.csrf.keys():
            self.assertEqual(token, token_)

    def test_check_csrf(self):
        user = DefaultNamespace()
        user.csrf = {}
        token = TokenCSRF.build_token(user)

        self.assertTrue(TokenCSRF.check_csrf(user, token))
        self.assertFalse(TokenCSRF.check_csrf(user, 0))

        token = TokenCSRF.build_token(user)

        for token in user.csrf.keys():
            user.csrf[token] -= 301

        self.assertFalse(TokenCSRF.check_csrf(user, token))

    def test_clean(self):
        user = DefaultNamespace()
        timestamp = time()
        user.csrf = {0: 0, 1: timestamp}

        TokenCSRF.clean(user, 1)
        self.assertDictEqual(user.csrf, {1: timestamp})

        TokenCSRF.clean(user, timestamp)
        self.assertDictEqual(user.csrf, {})


class TestSession(TestCase):
    def setUp(self):
        self.user = DefaultNamespace()
        self.user.id = 0

        self.ip = "127.0.0.1"
        self.session = Session(self.user, self.ip)

        self.pages = DefaultNamespace()
        self.pages.sessions = {}

        self.maxDiff = None

    def test___str__(self):
        self.assertRegex(
            str(self.session),
            r"Session\(Time=\d+\.\d+(e-\d{2})?, IP=127.0.0.1, Cookie=%(cookie)s, User=Default"
            r"Namespace\((__\w+__=(\[\]||\{\}), )+id=0\)\)"
            % {"cookie": self.session.cookie},
        )

    def test_build_session(self):
        token = Session.build_session(self.user, self.ip, self.pages)

        for session in self.pages.sessions.values():
            break

        self.assertEqual(f"0:{session.cookie}", token)

    def test_check_session(self):
        Session.build_session(self.user, self.ip, self.pages)

        for session in self.pages.sessions.values():
            break

        self.assertEqual(Session.check_session("", None, None, 0), 0)
        self.assertEqual(Session.check_session("SessionID=", None, None, 0), 0)
        self.assertEqual(
            Session.check_session("SessionID=abc:", None, None, 0), 0
        )
        self.assertEqual(
            Session.check_session("SessionID=1:", self.pages, None, 0), 0
        )
        self.assertEqual(
            Session.check_session("SessionID=0:", self.pages, "", 0), 0
        )
        self.assertEqual(
            Session.check_session("SessionID=0:", self.pages, self.ip, 0), 0
        )
        self.assertEqual(
            Session.check_session(
                f"SessionID=0:{session.cookie}", self.pages, self.ip, 0
            ),
            self.user,
        )
        session.time = 0
        self.assertEqual(
            Session.check_session(
                f"SessionID=0:{session.cookie}", self.pages, self.ip, 0
            ),
            0,
        )


if __name__ == "__main__":
    main()
