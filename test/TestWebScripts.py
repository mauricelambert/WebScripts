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

from unittest.mock import MagicMock, patch, Mock
from base64 import b64decode, b64encode
from unittest import TestCase, main
from types import ModuleType
from io import BytesIO
from os import path

import logging.config
import json
import sys

sys.path.append(path.join(path.dirname(__file__), ".."))

from WebScripts.WebScripts import Configuration, Server, WebScriptsConfigurationTypeError
from WebScripts.commons import Blacklist, Session

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': True
})
logging.disable()

class TestConfiguration(TestCase):

    def setUp(self):
        self.conf = Configuration()

    def test_add_conf(self):

        self.conf.List = ["0", "1"]
        self.conf.ListString = ["0", "1"]
        self.conf.Dict = {"0": "0", "1": "0"}
        self.conf.Value = "abc"

        self.conf.add_conf(**{
            "String": "qwerty",
            "None": None,
            "List": ["1", "2"],
            "Dict": {"1": "1", "2": "2"},
            "Int" : 1,
            "ListString": "1,2",
            "Value": None,
        })

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

        self.server = Server(self.conf)

    def test_check_blacklist(self):
        self.assertTrue(
            self.server.check_blacklist(None, "")
        )

        with patch.object(
            Blacklist, 
            'is_blacklist', 
            return_value=True,
        ) as mock_method:

            self.server.pages.ip_blacklist["ip"] = Blacklist(self.conf)
            self.assertFalse(
                self.server.check_blacklist(None, "ip")
            )

        with patch.object(
            Blacklist, 
            'is_blacklist', 
            return_value=False,
        ) as mock_method:

            self.server.pages.ip_blacklist["ip"] = Blacklist(self.conf)
            self.assertTrue(
                self.server.check_blacklist(None, "ip")
            )

        user = Mock()
        user.name = "a"
        user.id = 0

        self.assertTrue(
            self.server.check_blacklist(user, "")
        )

        with patch.object(
            Blacklist, 
            'is_blacklist', 
            return_value=True,
        ) as mock_method:

            self.server.pages.user_blacklist[0] = Blacklist(self.conf)
            self.assertFalse(
                self.server.check_blacklist(user, "")
            )

        with patch.object(
            Blacklist, 
            'is_blacklist', 
            return_value=False,
        ) as mock_method:

            self.server.pages.user_blacklist[0] = Blacklist(self.conf)
            self.assertTrue(
                self.server.check_blacklist(user, "")
            )

    def test_get_session(self):
        self.assertIsNone(self.server.get_session([], ""))
        self.assertIsNone(self.server.get_session(["SessionID="], ""))

        user = Mock()
        user.ip = "ip"

        with patch.object(
            Session, 
            'check_session', 
            return_value=user,
        ) as mock_method:

            self.assertEqual(
                self.server.get_session(["SessionID="], "ip"),
                user
            )
            self.assertTrue(user.check_csrf)

        with patch.object(
            Session, 
            'check_session', 
            return_value=user,
        ) as mock_method:

            user = self.server.get_session(["SessionID="], "")
            self.assertEqual(
                user.id, 1
            )
            self.assertEqual(
                user.ip, ""
            )
            self.assertEqual(
                user.name, "Unknow"
            )
            self.assertListEqual(
                user.groups, [0,1]
            )

    def test_check_auth(self):
        environ = {
            "HTTP_AUTHORIZATION": "Basic ",
            "HTTP_API_KEY": "",
            "HTTP_COOKIE": ";",
            "REMOTE_ADDR": "ip",
        }

        user, blacklisted = self.server.check_auth(
            {"REMOTE_ADDR": "ip"}
        )
        self.assertEqual(user.id, 0)
        self.assertEqual(user.name, "Not Authenticated")
        self.assertListEqual(
            user.groups, [0]
        )
        self.assertTrue(blacklisted)

        user = Mock()
        user.id = 2
        user.name = "Admin"
        user.groups = [50, 1000]
        user.ip = "ip"

        with patch.object(
            self.server, 
            'get_session', 
            return_value=user,
        ) as mock_method:

            user_2, blacklisted = self.server.check_auth(
                environ
            )
            self.assertTrue(blacklisted)
            self.assertEqual(user_2, user)

        del environ["HTTP_COOKIE"]

        user_2, blacklisted = self.server.check_auth(
            environ
        )

        self.assertEqual(user_2.id, 0)
        self.assertEqual(user_2.name, "Not Authenticated")
        self.assertListEqual(
            user_2.groups, [0]
        )
        self.assertTrue(blacklisted)

        with patch.object(
            self.server.pages, 
            'auth', 
            return_value=(None, {}, None),
        ) as mock_method:

            with patch.object(
                Session, 
                'check_session', 
                return_value=user,
            ) as mock_method:

                environ["HTTP_AUTHORIZATION"] += b64encode(b':').decode()
                user_2, blacklisted = self.server.check_auth(environ)

                self.assertTrue(blacklisted)
                self.assertEqual(user_2, user)

                del environ["HTTP_AUTHORIZATION"]

                user_2, blacklisted = self.server.check_auth(environ)

                self.assertTrue(blacklisted)
                self.assertEqual(user_2, user)

        with patch.object(
            self.server.pages, 
            'auth', 
            return_value=(None, {}, None),
        ) as mock_method:

            with patch.object(
                self.server, 
                'check_blacklist', 
                return_value=False,
            ) as mock_method:

                user_2, blacklisted = self.server.check_auth(environ)

                self.assertEqual(user_2.id, 0)
                self.assertEqual(user_2.name, "Not Authenticated")
                self.assertListEqual(
                    user_2.groups, [0]
                )
                self.assertFalse(blacklisted)

    def test_add_module_or_package(self):
        self.conf.modules_path = ["modules"]
        self.conf.modules = ["test"]

        default_path = sys.path.copy()

        self.server.add_module_or_package()
        self.assertListEqual(sys.path, default_path)
        
        try:
            self.assertTrue(self.server.pages.packages.test.is_imported)
        except:
            self.assertTrue(False)

    def test_add_paths(self):
        self.server.configuration.statics_path = [path.join("static", "css", "*.css")]
        self.server.configuration.js_path = [path.join("static", "js", "*.js")]
        self.server.add_paths()

        if self.server.pages.statics_paths.get("test.css"):
            self.assertTrue(True)
        else:
            self.assertTrue(False)

        if self.server.pages.js_paths.get("test.js"):
            self.assertTrue(True)
        else:
            self.assertTrue(False)

    def test_get_function_page(self):
        callable_, filename = self.server.get_function_page("/api/")
        self.assertEqual("", filename)
        self.assertEqual(callable_, self.server.pages.api)

        callable_, filename = self.server.get_function_page("/api/api.py")
        self.assertEqual("api.py", filename)
        self.assertEqual(callable_, self.server.pages.api)

        callable_, filename = self.server.get_function_page("/this/url/doesn't/exist")
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
        object_ = Mock(a=Mock(b=object))
        callable_, filename = self.server.get_attributes(object_, ["a", "b", "test"])
        
        self.assertIs(callable_, object)
        self.assertEqual(filename, "test")

        object_ = object()
        callable_, filename = self.server.get_attributes(object_, ["a", "bc", "test"])

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
        data = BytesIO(json.dumps({
            "arguments": {"-a": {"value": "abc", "input": False}},
            "csrf_token": "azerty",
        }).encode())
        environ = {
            "CONTENT_LENGTH": str(len(data.getvalue())),
            "wsgi.input": data,
        }

        arguments, csrf = self.server.parse_body(environ)
        self.assertEqual(csrf, "azerty")
        self.assertListEqual(
            arguments,
            [
                {'value': '-a', 'input': False},
                {'value': 'abc', 'input': False},
            ]
        )

        environ["CONTENT_LENGTH"] = "0"
        arguments, csrf = self.server.parse_body(environ)

        self.assertIsNone(csrf)
        self.assertListEqual(arguments, [])

    def test_app(self):
        environ = {
            "PATH_INFO": "/web/scripts/view_users.py",
            "REQUEST_METHOD": "",
            "REMOTE_ADDR": "",
        }

        self.server.page_401 = MagicMock(return_value="401")
        self.server.page_403 = MagicMock(return_value="403")
        self.server.page_404 = MagicMock(return_value="404")
        self.server.page_500 = MagicMock(return_value="500")

        self.server.parse_body = MagicMock(return_value=([], None))
        self.server.get_inputs = MagicMock(return_value=([], []))
        self.server.get_function_page = MagicMock(return_value=(None, None))

        with patch.object(
            self.server, 
            'check_auth', 
            return_value=(Mock(
                name="a", ip="ip", id=0, groups=[0]
            ), False),
        ) as mock_method:

            response = self.server.app(environ, Mock())
            self.assertEqual("403", response)

        self.server.check_auth = MagicMock(
            return_value=(
                Mock(ip="ip", id=1, name="name", groups=[50], check_csrf=False),
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

        page_2 = self.server.app(environ, Mock())
        self.assertListEqual(page, page_2)

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
            return_value=(MagicMock(return_value=("403", {}, b'')), None)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("403", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=("404", {}, b'')), None)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("404", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=("500", {}, b'')), None)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("500", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=None), None)
        )
        response = self.server.app(environ, Mock())
        self.assertEqual("500", response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=(None, {}, b'')), None)
        )
        response = self.server.app(environ, Mock())
        self.assertListEqual([b""], response)

        self.server.get_function_page = MagicMock(
            return_value=(MagicMock(return_value=(None, {}, '')), None)
        )
        response = self.server.app(environ, Mock())
        self.assertListEqual([b""], response)

    def test_send_headers(self):
        start_response = Mock()
        self.server.send_headers(start_response)
        start_response.assert_called_once_with(
            self.server.error,
            [(k,v) for k,v in self.server.headers.items()]
        )

        start_response = Mock()
        self.server.send_headers(start_response, error="500 Internal Server Error", headers={"Test": "Test"})
        headers = self.server.headers.copy()
        headers.update({"Test": "Test"})

        start_response.assert_called_once_with(
            "500 Internal Server Error",
            [(k,v) for k,v in headers.items()]
        )

    def test_page_500(self):
        a = object()

        with patch.object(
            self.server, 
            'send_error_page', 
            return_value=b'500',
        ) as mock_method:

            self.assertEqual(self.server.page_500('500', a), b'500')
        mock_method.assert_called_once_with(
            "500 Internal Error",
            b"500",
            a,
        )

    def test_page_404(self):
        a = object()

        with patch.object(
            self.server, 
            'send_error_page', 
            return_value=b'404',
        ) as mock_method:

            self.assertEqual(self.server.page_404('404', a), b'404')
        mock_method.assert_called_once_with(
            "404 Not Found",
            b"This URL: 404, doesn't exist on this server.\nURLs:\n\t - /api/\n\t - /web/",
            a,
        )

    def test_page_401(self):
        a = object()

        with patch.object(
            self.server, 
            'send_error_page', 
            return_value=b'401',
        ) as mock_method:

            self.assertEqual(self.server.page_401('401', a), b'401')
        mock_method.assert_called_once_with(
            "401 Unauthorized",
            b"Unauthorized (You don't have permissions)",
            a,
        )

    def test_page_403(self):
        a = object()

        with patch.object(
            self.server, 
            'send_error_page', 
            return_value=b'403',
        ) as mock_method:

            self.assertEqual(self.server.page_403('403', a), b'403')
        mock_method.assert_called_once_with(
            "403 Forbidden",
            b"Forbidden (You don't have permissions)",
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
            'send_custom_error',
            return_value=None,
        ) as mock_method:

            self.assertEqual(
                self.server.send_error_page(
                    "403 Forbidden",
                    b'',
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
            'send_custom_error',
            return_value=("401 Unauthorized", {"Content-Type": "text/html; charset=utf-8"}, b'401'),
        ) as mock_method:

            self.assertEqual(
                self.server.send_error_page(
                    "403 Forbidden",
                    b'',
                    a,
                ),
                b'401',
            )

        b.assert_called_once_with(
            a,
            "401 Unauthorized",
            {"Content-Type": "text/html; charset=utf-8"},
        )

        b = self.server.send_headers = Mock()
        self.server.debug = True

        page.append(b"\n\n")
        page.append(b'403')
        page.append(b'')

        with patch.object(
            self.server,
            'send_custom_error',
            return_value=("401 Unauthorized", {"Content-Type": "text/html; charset=utf-8"}, b'401'),
        ) as mock_method:

            self.assertEqual(
                self.server.send_error_page(
                    "403 Forbidden",
                    b'403',
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
        a = ModuleType('a')
        a.page_403 = Mock()

        self.server.pages.packages.a = a
        self.assertIsInstance(
            self.server.send_custom_error(
                "403 Forbidden", "403"
            ),
            Mock
        )

        a.page_403.assert_called_once_with("403 Forbidden")

if __name__ == '__main__':
    main()
