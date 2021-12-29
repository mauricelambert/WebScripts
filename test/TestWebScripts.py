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

"""
This file test the WebScripts.py file
"""

from unittest.mock import MagicMock, patch, Mock
from os import path, getcwd, chdir, rename
from unittest import TestCase, main
from argparse import Namespace
from importlib import reload
from base64 import b64encode
from types import ModuleType
from shutil import rmtree
from io import BytesIO
from time import time

import logging.config
import json
import sys
import os

dir_path = path.dirname(__file__)


def disable_logs():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})
    logging.disable()


disable_logs()

from WebScripts.WebScripts import (
    Configuration,
    Server,
    WebScriptsConfigurationError,
    WebScriptsConfigurationTypeError,
    parse_args,
    get_server_config,
    logs_configuration,
    configure_logs_system,
    add_configuration,
    send_mail,
    main,
)
from WebScripts.commons import Blacklist, Session
import WebScripts


class TestConfiguration(TestCase):
    def setUp(self):
        self.conf = Configuration()

    def test_add_conf(self):

        self.conf.List = ["0", "1"]
        self.conf.ListString = ["0", "1"]
        self.conf.Dict = {"0": "0", "1": "0"}
        self.conf.Value = "abc"

        self.conf.add_conf(
            **{
                "String": "qwerty",
                "None": None,
                "List": ["1", "2"],
                "Dict": {"1": "1", "2": "2"},
                "Int": 1,
                "ListString": "1,2",
                "Value": None,
            }
        )

        self.assertListEqual(self.conf.List, ["0", "1", "2"])
        self.assertListEqual(self.conf.ListString, ["0", "1", "2"])
        self.assertDictEqual(self.conf.Dict, {"0": "0", "1": "1", "2": "2"})
        self.assertEqual(self.conf.Int, 1)
        self.assertEqual(self.conf.Value, "abc")
        self.assertEqual(self.conf.String, "qwerty")

        with self.assertRaises(AttributeError):
            getattr(self.conf, "None")

        with self.assertRaises(WebScriptsConfigurationTypeError):
            self.conf.add_conf(**{"List": 1})


class TestServer(TestCase):
    def setUp(self):
        self.conf = Configuration()
        self.conf.interface = ""
        self.conf.port = 0
        self.conf.set_defaults()
        self.conf.build_types()

        self.conf_unsecure = Configuration()
        self.conf_unsecure.interface = ""
        self.conf_unsecure.port = 0
        self.conf_unsecure.security = False
        self.conf_unsecure.set_defaults()
        self.conf_unsecure.build_types()

        self.server = Server(self.conf)
        self.server_unsecure = Server(self.conf_unsecure)

        self.assertEqual(
            self.server_unsecure.headers[
                "Content-Security-Policy-Report-Only"
            ],
            "default-src 'self'; form-action 'none'; frame-ancestors 'none'; report-uri /csp/debug/",
        )
        self.assertListEqual(self.conf_unsecure.modules, ["csp"])
        self.assertListEqual(self.conf_unsecure.modules_path, ["modules"])
        self.assertListEqual(
            self.conf_unsecure.exclude_auth_pages,
            ["/api/", "/auth/", "/web/auth/", "/csp/debug/"],
        )

        self.conf_unsecure.modules = []
        self.conf_unsecure.modules_path = []
        delattr(self.server_unsecure.pages.packages, "csp")

    def test_check_blacklist(self):
        self.assertTrue(self.server.check_blacklist(None, ""))

        with patch.object(
            Blacklist,
            "is_blacklist",
            return_value=True,
        ) as mock_method:

            self.server.pages.ip_blacklist["ip"] = Blacklist(self.conf)
            self.assertFalse(self.server.check_blacklist(None, "ip"))

        with patch.object(
            Blacklist,
            "is_blacklist",
            return_value=False,
        ) as mock_method:

            self.server.pages.ip_blacklist["ip"] = Blacklist(self.conf)
            self.assertTrue(self.server.check_blacklist(None, "ip"))

        user = Mock()
        user.name = "a"
        user.id = 0

        self.assertTrue(self.server.check_blacklist(user, ""))

        with patch.object(
            Blacklist,
            "is_blacklist",
            return_value=True,
        ) as mock_method:

            self.server.pages.user_blacklist[0] = Blacklist(self.conf)
            self.assertFalse(self.server.check_blacklist(user, ""))

        with patch.object(
            Blacklist,
            "is_blacklist",
            return_value=False,
        ) as mock_method:

            self.server.pages.user_blacklist[0] = Blacklist(self.conf)
            self.assertTrue(self.server.check_blacklist(user, ""))

    def test_get_session(self):
        self.assertIsNone(self.server.get_session([], ""))
        self.assertIsNone(self.server.get_session(["SessionID="], ""))

        user = Mock()
        user.ip = "ip"

        with patch.object(
            Session,
            "check_session",
            return_value=user,
        ) as mock_method:

            self.assertEqual(
                self.server.get_session(["SessionID="], "ip"), user
            )
            self.assertTrue(user.check_csrf)

        with patch.object(
            Session,
            "check_session",
            return_value=user,
        ) as mock_method:

            user = self.server.get_session(["SessionID="], "")
            self.assertEqual(user.id, 1)
            self.assertEqual(user.ip, "")
            self.assertEqual(user.name, "Unknow")
            self.assertListEqual(user.groups, [0, 1])

    def test_check_origin(self):
        environ = {
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
            "SERVER_NAME": "webscripts.local",
        }
        environ_get = environ.get

        result = Server.check_origin(environ_get, environ)
        self.assertTrue(result)

        environ["HTTP_ORIGIN"] = "http://test.csrf.hack"

        result = Server.check_origin(environ_get, environ)
        self.assertFalse(result)

    def test_get_json_content(self):
        content = Server.get_json_content(
            b"{}", "application/json; charset=utf-8"
        )
        self.assertDictEqual(content, {})

        content = Server.get_json_content(
            b"error", "application/json; charset=utf-8"
        )
        self.assertIsNone(content)

        content = Server.get_json_content(b"{}", "text/plain; charset=utf-8")
        self.assertIsNone(content)

    def test_get_baseurl(self):
        environ = {
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
            "SERVER_NAME": "test",
        }
        environ_get = environ.get

        url = Server.get_baseurl(environ_get, environ)
        self.assertEqual(url, "http://webscripts.local")

        del environ["HTTP_HOST"]

        url = Server.get_baseurl(environ_get, environ)
        self.assertEqual(url, "http://test")

        environ["SERVER_PORT"] = "8000"

        url = Server.get_baseurl(environ_get, environ)
        self.assertEqual(url, "http://test:8000")

        environ["SERVER_PORT"] = "443"
        environ["wsgi.url_scheme"] = "https"

        url = Server.get_baseurl(environ_get, environ)
        self.assertEqual(url, "https://test")

        environ["SERVER_PORT"] = "4433"

        url = Server.get_baseurl(environ_get, environ)
        self.assertEqual(url, "https://test:4433")

    def test_set_default_headers(self):
        h = {}
        headers = {}
        c = Namespace()
        c.modules = []
        c.modules_path = []
        c.exclude_auth_pages = []

        Server.set_default_headers(h, True, c)

        headers[
            "Strict-Transport-Security"
        ] = "max-age=63072000; includeSubDomains; preload"
        headers["Content-Security-Policy"] = (
            "default-src 'self'; form-action 'none'; " "frame-ancestors 'none'"
        )
        headers["X-Frame-Options"] = "deny"
        headers["X-XSS-Protection"] = "1; mode=block"
        headers["X-Content-Type-Options"] = "nosniff"
        headers["Referrer-Policy"] = "origin-when-cross-origin"
        headers["Cache-Control"] = "no-store"
        headers["Pragma"] = "no-store"
        headers["Clear-Site-Data"] = '"cache", "executionContexts"'
        headers["Feature-Policy"] = (
            "payment 'none'; geolocation 'none'; "
            "microphone 'none'; camera 'none'"
        )
        headers[
            "Permissions-Policy"
        ] = "microphone=(),camera=(),payment=(),geolocation=()"
        headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["Cross-Origin-Resource-Policy"] = "same-origin"
        headers["X-Server"] = "WebScripts"

        self.assertDictEqual(h, headers)
        self.assertListEqual(c.modules, [])
        self.assertListEqual(c.modules_path, [])
        self.assertListEqual(c.exclude_auth_pages, [])

        h = {}
        Server.set_default_headers(h, False, c)
        self.assertDictEqual(
            h,
            {
                "Content-Security-Policy-Report-Only": (
                    "default-src 'self'; form-action 'none'; "
                    "frame-ancestors 'none'; report-uri /csp/debug/"
                )
            },
        )
        self.assertListEqual(c.modules, ["csp"])
        self.assertListEqual(c.modules_path, ["modules"])
        self.assertListEqual(c.exclude_auth_pages, ["/csp/debug/"])

    def test_use_basic_auth(self):
        def auth(cred, *args):
            if cred == ["--username", "Admin", "--password", "Admin"]:
                return True
            return False

        pages = Namespace()
        pages.auth = auth
        is_auth = Server.use_basic_auth(
            f'Basic {b64encode(b"Admin:Admin").decode()}', pages
        )

        self.assertTrue(is_auth)

        is_auth = Server.use_basic_auth(
            f'Basic {b64encode(b"AdminAdmin").decode()}', pages
        )
        self.assertIsNone(is_auth)

    def test_check_auth(self):
        environ = {
            # "HTTP_AUTHORIZATION": "Basic ",
            # "HTTP_API_KEY": "",
            "HTTP_COOKIE": ";",
            "HTTP_API_TOKEN": "SessionID=1:abc;test",
            "REMOTE_ADDR": "ip",
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
        }

        session = Mock()
        session.ip = "ip"
        session.time = time()
        session.cookie = "abc"
        session.user = Mock(name="abc", id=1)
        self.server.pages.sessions[1] = session

        user, not_blacklisted = self.server.check_auth({"REMOTE_ADDR": "ip"})
        self.assertEqual(user.id, 0)
        self.assertEqual(user.name, "Not Authenticated")
        self.assertListEqual(user.groups, [0])
        self.assertTrue(not_blacklisted)

        user = Mock()
        user.id = 2
        user.name = "Admin"
        user.groups = [50, 1000]
        user.ip = "ip"

        with patch.object(
            self.server,
            "get_session",
            return_value=user,
        ) as mock_method:

            user_2, not_blacklisted = self.server.check_auth(environ)
            self.assertTrue(not_blacklisted)
            self.assertEqual(user_2, user)

            # with patch.object(
            #     self.server,
            #     "check_blacklist",
            #     return_value=False,
            # ) as mock_method:

            #     user_2, not_blacklisted = self.server.check_auth(environ)

            #     self.assertEqual(user_2.id, 1)
            #     self.assertEqual(user_2.name, "Unknow")
            #     self.assertListEqual(user_2.groups, [0, 1])
            #     self.assertFalse(not_blacklisted)

        del environ["HTTP_COOKIE"]

        user_2, not_blacklisted = self.server.check_auth(environ)

        self.assertEqual(session.user.name, user_2.name)
        self.assertTrue(not_blacklisted)

        del environ["HTTP_API_TOKEN"]
        environ["HTTP_AUTHORIZATION"] = "Basic "
        environ["HTTP_API_KEY"] = ""

        user_2, not_blacklisted = self.server.check_auth(environ)

        self.assertEqual(user_2.id, 0)
        self.assertEqual(user_2.name, "Not Authenticated")
        self.assertListEqual(user_2.groups, [0])
        self.assertTrue(not_blacklisted)

        with patch.object(
            self.server.pages,
            "auth",
            return_value=(None, {}, None),
        ) as mock_method:

            with patch.object(
                Session,
                "check_session",
                return_value=user,
            ) as mock_method:

                environ["HTTP_AUTHORIZATION"] += b64encode(b":").decode()
                user_2, not_blacklisted = self.server.check_auth(environ)

                self.assertTrue(not_blacklisted)
                self.assertEqual(user_2, user)

                del environ["HTTP_AUTHORIZATION"]

                user_2, blacklisted = self.server.check_auth(environ)

                self.assertTrue(not_blacklisted)
                self.assertEqual(user_2, user)

        with patch.object(
            self.server.pages,
            "auth",
            return_value=(None, {}, None),
        ) as mock_method:

            with patch.object(
                self.server,
                "check_blacklist",
                return_value=False,
            ) as mock_method:

                user_2, not_blacklisted = self.server.check_auth(environ)

                self.assertEqual(user_2.id, 0)
                self.assertEqual(user_2.name, "Not Authenticated")
                self.assertListEqual(user_2.groups, [0])
                self.assertFalse(not_blacklisted)

    def test_add_module_or_package(self):
        if getcwd() == path.dirname(__file__):
            self.conf.modules_path = ["modules"]
        else:
            self.conf.modules_path = [
                path.join(path.dirname(__file__), "modules")
            ]
        self.conf.modules = ["test"]

        default_path = sys.path.copy()

        self.server.add_module_or_package()
        self.assertListEqual(sys.path, default_path)

        try:
            self.assertTrue(self.server.pages.packages.test.is_imported)
        except:
            self.assertTrue(False)

    def test_add_paths(self):
        if getcwd() == path.dirname(__file__):
            self.server.configuration.statics_path = [
                path.join("static", "css", "*.css")
            ]
            self.server.configuration.js_path = [
                path.join("static", "js", "*.js")
            ]
        else:
            self.server.configuration.statics_path = [
                path.join(path.dirname(__file__), "static", "css", "*.css")
            ]
            self.server.configuration.js_path = [
                path.join(path.dirname(__file__), "static", "js", "*.js")
            ]

        self.server.add_paths()

        self.assertIsNotNone(self.server.pages.statics_paths.get("test.css"))
        self.assertIsNotNone(self.server.pages.js_paths.get("test.js"))

        self.conf.auth_script = "test_auth_scripts.test"
        self.conf.active_auth = True
        with self.assertRaises(WebScriptsConfigurationError):
            self.server.add_paths()

    def test_get_function_page(self):
        callable_, filename, is_not_package = self.server.get_function_page(
            "/api/"
        )
        self.assertEqual("", filename)
        self.assertTrue(is_not_package)
        self.assertEqual(callable_, self.server.pages.api)

        callable_, filename, is_not_package = self.server.get_function_page(
            "/api/api.py"
        )
        self.assertTrue(is_not_package)
        self.assertEqual("api.py", filename)
        self.assertEqual(callable_, self.server.pages.api)

        callable_, filename, is_not_package = self.server.get_function_page(
            "/this/url/doesn't/exist"
        )
        self.assertFalse(is_not_package)
        self.assertIsNone(filename)
        self.assertIsNone(callable_)

    def test_get_URLs(self):
        urls = self.server.get_URLs()

        self.assertIn("/api/", urls)
        self.assertIn("/web/", urls)

        self.server.configuration.active_auth = True

        urls = self.server.get_URLs()
        self.assertIn("/auth/", urls)
        self.assertIn("/web/auth/", urls)

        self.server.pages.scripts = {"1": "1"}
        self.server.pages.statics_paths = {"1": "1"}
        self.server.pages.js_paths = {"1": "1"}
        self.server.pages.packages.test = ModuleType("test")

        urls = self.server.get_URLs()
        self.assertIn("/api/scripts/1", urls)
        self.assertIn("/web/scripts/1", urls)
        self.assertIn("/web/doc/1", urls)

        self.assertIn("/static/1", urls)
        self.assertIn("/js/1", urls)
        self.assertIn("/test/...", urls)

    def test_get_attributes(self):
        class CodeTest:
            def __init__(self):
                pass

            def methodTest1(self):
                pass

            def methodTest2(self, a, b, c, d, e, f, g):
                pass

            @staticmethod
            def methodTest3(a, b, c, d, e, f, g):
                pass

        object_ = Mock(a=Mock(b=object))
        callable_, filename, bool_ = self.server.get_attributes(
            object_, ["a", "b", "test"], True
        )

        self.assertTrue(bool_)
        self.assertIs(callable_, object)
        self.assertEqual(filename, "test")

        object_ = CodeTest()
        callable_, filename, bool_ = self.server.get_attributes(
            object_, ["methodTest2", "test"], False
        )

        self.assertFalse(bool_)
        self.assertEqual(callable_.__name__, object_.methodTest2.__name__)
        self.assertEqual(filename, "test")

        callable_, filename, bool_ = self.server.get_attributes(
            object_, ["methodTest3", "test"], False
        )

        self.assertFalse(bool_)
        self.assertEqual(callable_.__name__, object_.methodTest3.__name__)
        self.assertEqual(filename, "test")

        callable_, filename, bool_ = self.server.get_attributes(
            object_, ["methodTest1", "test"], True
        )

        self.assertTrue(bool_)
        self.assertIsNone(callable_)
        self.assertIsNone(filename)

        callable_, filename, bool_ = self.server.get_attributes(
            "test", ["test"], False
        )

        self.assertFalse(bool_)
        self.assertIsNone(callable_)
        self.assertIsNone(filename)

        object_ = object()
        callable_, filename, bool_ = self.server.get_attributes(
            object_, ["a", "bc", "test"]
        )

        self.assertTrue(bool_)
        self.assertIsNone(callable_)
        self.assertIsNone(filename)

    def test_get_inputs(self):
        arguments = [
            {"value": 1, "input": True},
            {"value": 2, "input": False},
        ]
        inputs, arguments = self.server.get_inputs(arguments)

        self.assertListEqual(inputs, ["1"])
        self.assertListEqual(arguments, [2])

    def test_parse_body(self):
        data = BytesIO(
            json.dumps(
                {
                    "arguments": {"-a": {"value": "abc", "input": False}},
                    "csrf_token": "azerty",
                }
            ).encode()
        )
        environ = {
            "CONTENT_LENGTH": str(len(data.getvalue())),
            "wsgi.input": data,
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
            "SERVER_NAME": "webscripts.local",
            "CONTENT_TYPE": "application/json",
        }

        arguments, csrf, is_webscripts_request = self.server.parse_body(
            environ
        )
        self.assertTrue(is_webscripts_request)
        self.assertEqual(csrf, "azerty")
        self.assertListEqual(
            arguments,
            [
                {"value": "-a", "input": False},
                {"value": "abc", "input": False},
            ],
        )

        environ["CONTENT_LENGTH"] = "0"
        arguments, csrf, is_webscripts_request = self.server.parse_body(
            environ
        )
        self.assertTrue(is_webscripts_request)
        self.assertIsNone(csrf)
        self.assertListEqual(arguments, [])

        environ["CONTENT_LENGTH"] = "abc"
        arguments, csrf, is_webscripts_request = self.server.parse_body(
            environ
        )
        self.assertTrue(is_webscripts_request)
        self.assertIsNone(csrf)
        self.assertListEqual(arguments, [])

        data = BytesIO(
            json.dumps(
                {
                    "": {"-a": {"value": "abc", "input": False}},
                    "csrf_token": "azerty",
                }
            ).encode()
        )
        environ = {
            "CONTENT_LENGTH": str(len(data.getvalue())),
            "wsgi.input": data,
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
            "SERVER_NAME": "webscripts.local",
            "CONTENT_TYPE": "application/json",
        }

        arguments, csrf, is_webscripts_request = self.server.parse_body(
            environ
        )
        self.assertFalse(is_webscripts_request)
        self.assertIsNone(csrf)
        self.assertDictEqual(
            arguments,
            {
                "": {"-a": {"value": "abc", "input": False}},
                "csrf_token": "azerty",
            },
        )

        data = BytesIO(b"abc")
        environ = {
            "CONTENT_LENGTH": str(len(data.getvalue())),
            "wsgi.input": data,
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
            "SERVER_NAME": "webscripts.local",
            "CONTENT_TYPE": "application/json",
        }

        arguments, csrf, is_webscripts_request = self.server.parse_body(
            environ
        )
        self.assertFalse(is_webscripts_request)
        self.assertIsNone(csrf)
        self.assertEqual(arguments, b"abc")

        environ = {
            "wsgi.url_scheme": "https",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://test.hack.csrf",
            "SERVER_PORT": "8000",
            "SERVER_NAME": "webscripts.local",
            "CONTENT_TYPE": "application/json",
        }

        arguments, csrf, is_webscripts_request = self.server.parse_body(
            environ
        )

        self.assertFalse(is_webscripts_request)
        self.assertIsNone(csrf)
        self.assertListEqual(arguments, [])

    def test_app(self):
        environ = {
            "PATH_INFO": "/static/test.css",
            "REQUEST_METHOD": "",
            "REMOTE_ADDR": "",
            "CONTENT_LENGTH": "4",
            "wsgi.input": BytesIO(b"test"),
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "webscripts.local",
            "HTTP_ORIGIN": "http://webscripts.local",
            "SERVER_PORT": "80",
            "SERVER_NAME": "webscripts.local",
        }

        self.server.page_400 = MagicMock(return_value="400")
        self.server.page_401 = MagicMock(return_value="401")
        self.server.page_403 = MagicMock(return_value="403")
        self.server.page_404 = MagicMock(return_value="404")
        self.server.page_406 = MagicMock(return_value="406")
        self.server.page_500 = MagicMock(return_value="500")

        self.server.parse_body = MagicMock(return_value=([], None, False))
        self.server.get_inputs = MagicMock(return_value=([], []))
        self.server.get_function_page = MagicMock(
            return_value=(Mock(), None, True)
        )

        with patch.object(
            self.server,
            "check_auth",
            return_value=(Mock(name="a", ip="ip", id=0, groups=[0]), False),
        ) as mock_method:

            response = self.server.app(environ, Mock())
            self.assertEqual("403", response)

        self.server.check_auth = MagicMock(
            return_value=(
                Mock(
                    ip="ip", id=1, name="name", groups=[50], check_csrf=False
                ),
                True,
            )
        )

        page = [
            b"Authentication required:\n\t",
            b" - For API you can use Basic Auth",
            b"\n\t - For API you can use Api-Key",
            b"\n\t - For Web Interface (with Web Browser) use /web/auth/",
        ]
        self.server.configuration.accept_unknow_user = False
        self.server.configuration.accept_unauthenticated_user = False
        self.server.configuration.active_auth = True

        self.assertEqual(self.server.app(environ, Mock()), "400")

        environ["REQUEST_METHOD"] = "POST"

        self.assertEqual(self.server.app(environ, Mock()), "406")
        self.server.parse_body = MagicMock(return_value=([], None, True))

        environ["PATH_INFO"] = "/web/scripts/view_users.py"
        self.server.get_function_page = MagicMock(
            return_value=(None, None, True)
        )

        page_2 = self.server.app(environ, Mock())
        self.assertListEqual(page, page_2)

        self.conf.exclude_auth_pages.append("/web/scripts/view_users.py")

        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page, page_2)

        self.conf.exclude_auth_pages.pop()
        self.conf.exclude_auth_paths.append("/web/scripts/view")

        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page, page_2)

        self.conf.exclude_auth_paths.pop()

        page_2 = self.server.app(environ, Mock())
        self.assertListEqual(page, page_2)

        self.server.configuration.active_auth = False
        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page_2, page)

        self.server.configuration.active_auth = True
        environ["PATH_INFO"] = "/auth/"
        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page_2, page)

        environ["PATH_INFO"] = "/web/auth/"
        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page_2, page)

        environ["PATH_INFO"] = "/js/test.js"
        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page_2, page)

        environ["PATH_INFO"] = "/static/test.css"
        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page_2, page)

        environ["PATH_INFO"] = "/api/"
        page_2 = self.server.app(environ, Mock())
        self.assertNotEqual(page_2, page)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=("403", {}, b"")), None, True)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("403", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=("404", {}, b"")), None, True)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("404", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=("500", {}, b"")), None, True)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("500", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=None), None, True)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("500", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=(None, {}, b"")), None, True)
        )
        response = self.server.app(environ, Mock())
        self.assertListEqual([b""], response)

        environ["REQUEST_METHOD"] = "GET"
        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=(None, {}, "")), None, True)
        )
        response = self.server.app(environ, Mock())
        self.assertListEqual([b""], response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=("451", {}, "")), None, True)
        )
        self.server.send_custom_error = MagicMock(
            return_value=("200", {}, "abc")
        )
        response = self.server.app(environ, Mock())
        self.assertListEqual([b"abc"], response)

        environ["REQUEST_METHOD"] = "HEAD"
        response = self.server.app(environ, Mock())
        self.assertListEqual([], response)

    def test_set_default_values_for_response(self):
        e, h = self.server.set_default_values_for_response("", {})
        self.assertEqual(e, self.server.error)
        self.assertEqual(h, self.server.headers)

        e, h = self.server.set_default_values_for_response(None, {})
        self.assertEqual(e, self.server.error)
        self.assertEqual(h, self.server.headers)

        e, h = self.server.set_default_values_for_response(
            "456 NOK", {"test": "test"}
        )
        h2 = self.server.headers.copy()
        h2["test"] = "test"
        self.assertEqual(e, "456 NOK")
        self.assertEqual(h, h2)

    def test_get_content_length(self):

        v = self.server.get_content_length({"CONTENT_LENGTH": "10"})
        self.assertEqual(v, 10)

        v = self.server.get_content_length({"CONTENT_LENGTH": "abc"})
        self.assertEqual(v, 0)

        v = self.server.get_content_length({})
        self.assertEqual(v, 0)

    def test_return_inputs(self):
        request = [
            {"value": "test1", "input": False},
            {"value": "test2", "input": True},
        ]
        a, i = self.server.return_inputs(request, True)

        self.assertListEqual(a, ["test1"])
        self.assertListEqual(i, ["test2"])

        a, i = self.server.return_inputs(request, False)

        self.assertListEqual(a, request)
        self.assertListEqual(i, [])

    def test_try_get_command(self):
        v = self.server.try_get_command({})
        self.assertIsNone(v)

        v1, v2, v3 = self.server.try_get_command({"arguments": 1})
        self.assertDictEqual(v1, {"arguments": 1})
        self.assertIsNone(v2)
        self.assertFalse(v3)

        v1, v2, v3 = self.server.try_get_command(
            {
                "csrf_token": "1",
                "arguments": {"test": {"value": 1, "input": False}},
            }
        )
        self.assertListEqual(v1, [{"value": "1", "input": False}])
        self.assertEqual(v2, "1")
        self.assertTrue(v3)

    def test_return_page(self):
        response = self.server.return_page(b"")
        self.assertListEqual([b""], response)

        response = self.server.return_page("")
        self.assertListEqual([b""], response)

        response = self.server.return_page([b""])
        self.assertListEqual([b""], response)

    def test_send_headers(self):
        start_response = Mock()
        self.server.send_headers(start_response)
        start_response.assert_called_once_with(
            self.server.error, [(k, v) for k, v in self.server.headers.items()]
        )

        start_response = Mock()
        self.server.send_headers(
            start_response,
            error="500 Internal Server Error",
            headers={"Test": "Test"},
        )
        headers = self.server.headers.copy()
        headers.update({"Test": "Test"})

        start_response.assert_called_once_with(
            "500 Internal Server Error", [(k, v) for k, v in headers.items()]
        )

    def test_page_400(self):
        a = object()

        with patch.object(
            self.server,
            "send_error_page",
            return_value=b"400",
        ) as mock_method:

            self.assertEqual(self.server.page_400("AUTH", a), b"400")
        mock_method.assert_called_once_with(
            "400 Bad Request",
            b"Bad method, method should be GET, POST or HEAD not AUTH",
            a,
        )

    def test_page_500(self):
        a = object()

        with patch.object(
            self.server,
            "send_error_page",
            return_value=b"500",
        ) as mock_method:

            self.assertEqual(self.server.page_500("500", a), b"500")
        mock_method.assert_called_once_with(
            "500 Internal Error",
            b"500",
            a,
        )

    def test_page_404(self):
        a = object()

        with patch.object(
            self.server,
            "send_error_page",
            return_value=b"404",
        ) as mock_method:

            self.assertEqual(self.server.page_404("404", a), b"404")
        mock_method.assert_called_once_with(
            "404 Not Found",
            b"This URL: 404, doesn't exist on this server.\nURLs:\n\t - /api/\n\t - /web/",
            a,
        )

    def test_page_401(self):
        a = object()

        with patch.object(
            self.server,
            "send_error_page",
            return_value=b"401",
        ) as mock_method:

            self.assertEqual(self.server.page_401("401", a), b"401")
        mock_method.assert_called_once_with(
            "401 Unauthorized",
            b"Unauthorized (You don't have permissions)",
            a,
        )

    def test_page_403(self):
        a = object()

        with patch.object(
            self.server,
            "send_error_page",
            return_value=b"403",
        ) as mock_method:

            self.assertEqual(self.server.page_403("403", a), b"403")
        mock_method.assert_called_once_with(
            "403 Forbidden",
            b"Forbidden (You don't have permissions)",
            a,
        )

    def test_page_406(self):
        a = object()

        with patch.object(
            self.server,
            "send_error_page",
            return_value=b"406",
        ) as mock_method:

            self.assertEqual(self.server.page_406("406", a), b"406")
        mock_method.assert_called_once_with(
            "406 Not Acceptable",
            b"Not Acceptable, your request is not a valid WebScripts request.",
            a,
        )

    def test_send_error_page(self):
        a = object()
        self.server.configuration = None
        page = [
            b"---------------\n",
            b"** ERROR 403 **\n",
            b"---------------\n",
        ]
        b = self.server.send_headers = Mock()

        with patch.object(
            self.server,
            "send_custom_error",
            return_value=None,
        ) as mock_method:

            self.assertEqual(
                self.server.send_error_page(
                    "403 Forbidden",
                    b"",
                    a,
                ),
                page,
            )

        b.assert_called_once_with(
            a,
            "403 Forbidden",
            {"Content-Type": "text/plain; charset=utf-8"},
        )

        b = self.server.send_headers = Mock()

        with patch.object(
            self.server,
            "send_custom_error",
            return_value=(
                "401 Unauthorized",
                {"Content-Type": "text/html; charset=utf-8"},
                b"401",
            ),
        ) as mock_method:

            self.assertEqual(
                self.server.send_error_page(
                    "403 Forbidden",
                    b"",
                    a,
                ),
                b"401",
            )

        b.assert_called_once_with(
            a,
            "401 Unauthorized",
            {"Content-Type": "text/html; charset=utf-8"},
        )

        b = self.server.send_headers = Mock()
        self.server.debug = True

        page.append(b"\n\n")
        page.append(b"403")
        page.append(b"")

        with patch.object(
            self.server,
            "send_custom_error",
            return_value=(
                "401 Unauthorized",
                {"Content-Type": "text/html; charset=utf-8"},
                b"401",
            ),
        ) as mock_method:

            self.assertEqual(
                self.server.send_error_page(
                    "403 Forbidden",
                    b"403",
                    a,
                ),
                page,
            )

        b.assert_called_once_with(
            a,
            "403 Forbidden",
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    def test_send_custom_error(self):
        a = ModuleType("a")
        a.page_403 = Mock()

        self.server.pages.packages.a = a
        self.assertIsInstance(
            self.server.send_custom_error("403 Forbidden", "403"), Mock
        )

        a.page_403.assert_called_once_with("403 Forbidden")


class TestFunctions(TestCase):
    def setUp(self):
        self.conf = Configuration()
        self.conf.interface = ""
        self.conf.port = 0
        self.conf.set_defaults()
        self.conf.build_types()

        self.server = Server(self.conf)

    @patch.object(
        WebScripts.WebScripts.simple_server,
        "make_server",
        Mock(
            return_value=Mock(
                serve_forever=Mock(side_effect=KeyboardInterrupt())
            )
        ),
    )
    def test_main(self):
        global WebScripts

        def raise_keyboard(self):
            raise KeyboardInterrupt

        WebScripts.__name__ = "__main__"
        argv = sys.argv.copy()
        sys.argv = ["WebScripts", "--debug"]
        WebScripts.main()

        WebScripts.argv = ["WebScripts", "--test-running"]
        WebScripts.main()
        sys.argv = argv

    def test_parse_args(self):
        argv = sys.argv.copy()
        sys.argv = ["WebScripts"]
        arguments = parse_args()

        for config, value in arguments.__dict__.items():
            if value is None:
                self.assertIsNone(value)  # always pass
            else:
                self.assertEqual(len(value), 0)

        sys.argv = argv

    def test_get_server_config(self):
        argv = sys.argv.copy()
        sys.argv = [
            "WebScripts",
            "--config-cfg",
            "test_inexistant_file",
            "test.ini",
            "test/test.ini",
            "--config-json",
            "test_inexistant_file",
            "test.json",
            "test/test.json",
        ]
        arguments = parse_args()

        with open("test.json", "w") as f:
            f.write('{"server": {}}')

        with open("test.ini", "w") as f:
            f.write("[server]\n")

        for configurations in get_server_config(arguments):
            self.assertTrue(isinstance(configurations, dict))

        arguments = parse_args()
        with patch.object(
            WebScripts.WebScripts,
            "system",
            return_value="Linux"
            if WebScripts.WebScripts.system() == "Windows"
            else "Windows",
        ) as mock_method:
            for configurations in get_server_config(arguments):
                self.assertTrue(isinstance(configurations, dict))

        sys.argv = argv

        os.remove("test.json")
        os.remove("test.ini")

    def test_logs_configuration(self):
        logs_configuration(self.conf)
        self.conf.log_level = "0"
        logs_configuration(self.conf)
        self.conf.log_level = "DEBUG"
        logs_configuration(self.conf)

        self.conf.log_level = []
        with self.assertRaises(WebScriptsConfigurationError):
            logs_configuration(self.conf)

        disable_logs()

    def test_configure_logs_system(self):
        global WebScripts

        def raise_permission(file):
            raise PermissionError

        if path.isdir("logs"):
            rmtree("logs", ignore_errors=True)

        configure_logs_system()
        disable_logs()

        self.assertTrue(path.isdir("logs"))
        self.assertTrue(path.isfile(path.join("logs", "root.logs")))

        if path.isdir("logs"):
            rmtree("logs", ignore_errors=True)

        WebScripts.mkdir = raise_permission
        sys.modules["os"].mkdir = raise_permission
        WebScripts.mkdir = Mock(side_effect=PermissionError())

        configure_logs_system()
        disable_logs()

    def test_add_configuration(self):
        conf = {"server": {"test1": "test1"}, "test2": "test2"}
        conf_based = Configuration()

        new_conf = add_configuration(conf_based, conf)

        self.assertIs(new_conf, conf_based)
        self.assertEqual(conf_based.test1, "test1")
        self.assertEqual(conf_based.test2, "test2")

    def test_send_mail(self):
        self.assertEqual(send_mail(self.conf, "test"), 1)

        self.server.pages.packages.error_pages = Mock(
            Request=Mock(send_mail=Mock())
        )
        self.assertEqual(send_mail(self.conf, "test"), 0)


if __name__ == "__main__":
    main()
