#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tools run scripts and display the result in a Web Interface.
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

"""This tools run scripts and display the result in a Web Interface.

This file is the "main" file of this package (implement the main function,
the Server class and the Configuration class)."""

__version__ = "0.0.12"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This tools run scripts and display the result in a Web
Interface.

This file is the "main" file of this package (implement the main function,
the Server class and the Configuration class)."""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Configuration", "Server", "main"]

from types import SimpleNamespace, ModuleType, FunctionType
from collections.abc import Iterator, Callable
from argparse import Namespace, ArgumentParser
from typing import TypeVar, Tuple, List, Dict
from os import path, _Environ, getcwd, mkdir
from wsgiref import simple_server
from threading import Thread
from base64 import b64decode
from glob import iglob
import traceback
import platform
import logging
import json
import sys

if __package__:
    from .hardening import main as hardening
    from .Pages import (
        Pages,
        Argument,
        User,
        Session,
        ScriptConfig,
        CallableFile,
        JsonValue,
        DefaultNamespace,
        get_ini_dict,
        lib_directory as server_path,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_arguments_count,
        # doRollover,
        # rotator,
        # namer,
        # Handler,
        #        get_real_path,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )
else:
    from hardening import main as hardening
    from Pages import (
        Pages,
        Argument,
        User,
        Session,
        ScriptConfig,
        CallableFile,
        JsonValue,
        DefaultNamespace,
        get_ini_dict,
        lib_directory as server_path,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_arguments_count,
        # doRollover,
        # rotator,
        # namer,
        # Handler,
        #        get_real_path,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )

NameSpace = TypeVar("NameSpace", SimpleNamespace, Namespace)
FunctionOrNone = TypeVar("FunctionOrNone", FunctionType, None)
Content = TypeVar(
    "Content", List[Dict[str, JsonValue]], Dict[str, JsonValue], bytes
)


class Configuration(DefaultNamespace):

    """This class build the configuration from dict(s) with
    configuration files and arguments."""

    __defaults__ = {
        "interface": "127.0.0.1",
        "port": 8000,
        "modules": [],
        "js_path": [],
        "log_level": 0,
        "statics_path": [],
        "scripts_path": [],
        "modules_path": [],
        "exclude_auth_paths": ["/static/", "/js/"],
        "exclude_auth_pages": ["/api/", "/auth/", "/web/auth/"],
        "auth_script": None,
        "active_auth": False,
        "documentations_path": [],
        "accept_unknow_user": True,
        "accept_unauthenticated_user": True,
    }
    __required__ = ("interface", "port")
    __optional__ = (
        "debug",
        "security",
        "active_auth",
        "auth_script",
        "accept_unknow_user",
        "accept_unauthenticated_user",
        "exclude_auth_paths",
        "exclude_auth_pages",
        "modules",
        "modules_path",
        "js_path",
        "statics_path",
        "documentations_path",
        "scripts_path",
        "json_scripts_config",
        "ini_scripts_config" "log_level",
        "log_filename",
        "log_level",
        "log_format",
        "log_date_format",
        "log_encoding",
        "auth_failures_to_blacklist",
        "blacklist_time",
        "smtp_server",
        "smtp_starttls",
        "smtp_password",
        "smtp_port",
        "smtp_ssl",
        "admin_adresses",
        "notification_address",
    )
    __types__ = {
        "port": int,
        "debug": bool,
        "security": bool,
        "active_auth": bool,
        "accept_unknow_user": bool,
        "accept_unauthenticated_user": bool,
        "modules": list,
        "modules_path": list,
        "js_path": list,
        "statics_path": list,
        "documentations_path": list,
        "scripts_path": list,
        "json_scripts_config": list,
        "ini_scripts_config": list,
        "auth_failures_to_blacklist": int,
        "blacklist_time": int,
        "smtp_starttls": bool,
        "smtp_port": int,
        "smtp_ssl": bool,
        "admin_adresses": list,
    }

    @log_trace
    def add_conf(self, **kwargs):

        """Add configurations from other configuration files found."""

        for key, value in kwargs.items():

            if value is not None:

                Logs.info(f"Add configuration {key}: {value}")
                default_value = self.__dict__.get(key)

                if isinstance(default_value, list):
                    if isinstance(value, str):
                        value = value.split(",")

                    if isinstance(value, list):
                        for value_ in value:
                            if value_ not in self.__dict__[key]:
                                self.__dict__[key].append(value_)
                    else:
                        raise WebScriptsConfigurationTypeError(
                            f"Configuration list {key}: {value} can't be "
                            f"add to {default_value}"
                        )

                elif isinstance(default_value, dict):
                    self.__dict__[key].update(value)
                else:
                    self.__dict__[key] = value


class Server:

    """This class implement the WebScripts server."""

    @log_trace
    def __init__(self, configuration: Configuration):
        self.configuration = configuration
        self.interface: str = configuration.interface
        self.port: int = configuration.port

        self.user: Dict[str, User] = {}
        self.unknow: Dict = {"id": 1, "name": "Unknow", "groups": [0, 1]}
        self.not_authenticated: Dict = {
            "id": 0,
            "name": "Not Authenticated",
            "groups": [0],
        }
        self.error: str = "200 OK"
        self.pages = Pages()

        self.version = (
            sys.modules[__package__].__version__
            if __package__
            else __version__
        )
        self.headers = {
            "Server": f"WebScripts {self.version}",
            "Content-Type": "text/html; charset=utf-8",
        }

        self.debug = getattr(configuration, "debug", False)
        self.security = getattr(configuration, "security", True)
        self.loglevel = getattr(configuration, "log_level", "DEBUG")

        if self.security:
            self.headers[
                "Strict-Transport-Security"
            ] = "max-age=63072000; includeSubDomains; preload"
            self.headers["Content-Security-Policy"] = (
                "default-src 'self'; form-action 'none'; "
                "frame-ancestors 'none'"
            )
            self.headers["X-Frame-Options"] = "deny"
            self.headers["X-XSS-Protection"] = "1; mode=block"
            self.headers["X-Content-Type-Options"] = "nosniff"
            self.headers["Referrer-Policy"] = "origin-when-cross-origin"
            self.headers["Cache-Control"] = "no-store"
            self.headers["Pragma"] = "no-store"
            self.headers["Clear-Site-Data"] = '"cache", "executionContexts"'
            self.headers["Feature-Policy"] = (
                "payment 'none'; geolocation 'none'; "
                "microphone 'none'; camera 'none'"
            )
            self.headers[
                "Permissions-Policy"
            ] = "microphone=(),camera=(),payment=(),geolocation=()"
            self.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
            self.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            self.headers["Cross-Origin-Resource-Policy"] = "same-origin"
            self.headers["X-Server"] = "WebScripts"
        else:
            if "csp" not in configuration.modules:
                configuration.modules.append("csp")
            if "modules" not in configuration.modules_path:
                configuration.modules_path.append("modules")
            if "/csp/debug/" not in configuration.exclude_auth_pages:
                configuration.exclude_auth_pages.append("/csp/debug/")

            self.headers["Content-Security-Policy-Report-Only"] = (
                "default-src 'self'; form-action 'none'; "
                "frame-ancestors 'none'; report-uri /csp/debug/"
            )

        self.add_module_or_package()
        self.add_paths()

    @log_trace
    def check_blacklist(self, user: User, ip: str) -> bool:

        """This function checks that the IP and the
        username are not in the blacklist."""

        if user is not None:
            name = user.name
            user = self.pages.user_blacklist.get(user.id, None)
            if user is not None and user.is_blacklist(self.configuration):
                Logs.critical(
                    f"User {name} is blacklisted "
                    f"({user.counter} attempt using IP {ip})"
                )
                return False

        ip_ = self.pages.ip_blacklist.get(ip, None)
        if ip_ is not None and ip_.is_blacklist(self.configuration):
            Logs.critical(f"IP {ip} is blacklisted ({ip_.counter} attempt).")
            return False

        return True

    @log_trace
    def get_session(self, cookies: List[str], ip: str) -> User:

        """This function return User from cookies."""

        for cookie in cookies:
            if cookie.startswith("SessionID="):
                user = Session.check_session(
                    cookie,
                    self.pages,
                    ip,
                    None,
                    getattr(self.configuration, "session_max_time", 3600),
                )

                if user is None:
                    continue

                if ip != user.ip:
                    user = User.default_build(
                        ip=ip, check_csrf=True, **self.unknow
                    )
                else:
                    user.check_csrf = True

                return user

    def check_auth(self, environ: _Environ) -> Tuple[User, bool]:

        """This function check if user is authenticated and blacklisted."""

        credentials = environ.get("HTTP_AUTHORIZATION")
        api_key = environ.get("HTTP_API_KEY")
        cookies = environ.get("HTTP_COOKIE")
        ip = get_ip(environ)
        user = None
        headers = None

        if cookies is not None:
            user = self.get_session(cookies.split("; "), ip)

        elif credentials is not None and credentials.startswith("Basic "):
            credentials = b64decode(
                credentials.split(" ", maxsplit=1)[1]
            ).decode()

            if ":" in credentials:
                username, password = credentials.split(":", maxsplit=1)
                code, headers, content = self.pages.auth(
                    environ,
                    User.default_build(ip=ip, **self.not_authenticated),
                    self.configuration,
                    self.configuration.auth_script,
                    ["--username", username, "--password", password],
                    [],
                )

        elif api_key is not None:
            code, headers, content = self.pages.auth(
                environ,
                User.default_build(ip=ip, **self.not_authenticated),
                self.configuration,
                self.configuration.auth_script,
                ["--api-key", api_key],
                [],
            )

        if headers is not None:
            cookie = headers.get("Set-Cookie", "").split("; ")[0]
            user = Session.check_session(
                cookie,
                self.pages,
                ip,
                None,
                getattr(self.configuration, "session_max_time", 3600),
            )

        not_blacklisted = self.check_blacklist(user, ip)
        if user is not None and not_blacklisted:
            return user, not_blacklisted

        if user is None:
            return (
                User.default_build(ip=ip, **self.not_authenticated),
                not_blacklisted,
            )
        else:
            return User.default_build(ip=ip, **self.unknow), not_blacklisted

    @log_trace
    def add_module_or_package(self) -> None:

        """This function add packages and modules to build custom page."""

        modules_path = []
        for module_path in self.configuration.modules_path[::-1]:
            modules_path.append(module_path)
            modules_path.append(path.join(server_path, module_path))

        sys.path = modules_path + sys.path

        Pages.packages = DefaultNamespace()
        for package in self.configuration.modules:
            Logs.warning(f"Add package/module named: {package}")

            package = __import__(package)
            setattr(Pages.packages, package.__name__, package)

        for path_ in modules_path:
            sys.path.remove(path_)

    @log_trace
    def add_paths(self) -> None:

        """This function add js, static and scripts paths."""

        Pages.scripts = ScriptConfig.build_scripts_from_configuration(
            self.configuration
        )

        current_directory = getcwd()

        Pages.statics_paths = {}
        Pages.js_paths = {}

        for dirname in (server_path, current_directory):
            for js_glob in self.configuration.js_path:

                js_glob = path.join(dirname, path.normcase(js_glob))
                for js_file in iglob(js_glob):
                    filename = path.basename(js_file)
                    file_path = path.abspath(js_file)

                    Logs.info(f"Find a javascript file: {file_path}")

                    Pages.js_paths[filename] = CallableFile(
                        "js", file_path, filename
                    )

            for static_glob in self.configuration.statics_path:

                static_glob = path.join(dirname, path.normcase(static_glob))
                for static_file in iglob(static_glob):
                    filename = path.basename(static_file)
                    file_path = path.abspath(static_file)

                    Logs.info(f"Find a static file: {file_path}")

                    Pages.statics_paths[filename] = CallableFile(
                        "static", file_path, filename
                    )

        if (
            self.configuration.active_auth
            and self.configuration.auth_script not in Pages.scripts.keys()
        ):
            raise WebScriptsConfigurationError(
                "Auth script not found in configurations."
            )

    @log_trace
    def get_function_page(self, path: str) -> Tuple[FunctionOrNone, str, bool]:

        """This function find function from URL path.
        If the function is a WebScripts built-in function,
        return the function, filename and True. Else return the
        function, filename and False."""

        path = path.split("/")
        del path[0]

        default, filename, _ = self.get_attributes(self.pages, path)

        if default is not None:
            return default, filename, True
        else:
            return self.get_attributes(self.pages.packages, path, False)

    @log_trace
    def get_URLs(self) -> List[str]:

        """This function return a list of urls (scripts, documentation...)
        and the start of the URL of custom packages."""

        urls = ["/api/", "/web/"]

        if getattr(self.configuration, "active_auth", None):
            urls.append("/auth/")
            urls.append("/web/auth/")

        for script_name in self.pages.scripts.keys():
            urls.append(f"/web/scripts/{script_name}")
            urls.append(f"/api/scripts/{script_name}")
            urls.append(f"/web/doc/{script_name}")

        for js_name in self.pages.js_paths.keys():
            urls.append(f"/js/{js_name}")

        for static_name in self.pages.statics_paths.keys():
            urls.append(f"/static/{static_name}")

        for package in dir(self.pages.packages):
            if isinstance(getattr(self.pages.packages, package), ModuleType):
                urls.append(f"/{package}/...")

        return urls

    @log_trace
    def get_attributes(
        self,
        object_: object,
        attributes: List[str],
        is_not_package: bool = True,
    ) -> Tuple[FunctionOrNone, str, bool]:

        """This function get recursive attribute from object."""

        for attribute in attributes[:-1]:
            object_ = getattr(object_, attribute, None)

            if object_ is None:
                return None, None, is_not_package

        arg_count = get_arguments_count(object_)

        if isinstance(object_, Callable) and (
            arg_count == 7 or arg_count == 8
        ):
            return object_, attributes[-1], is_not_package
        else:
            return None, None, is_not_package

    @log_trace
    def get_inputs(
        self, arguments: List[Dict[str, JsonValue]]
    ) -> Tuple[List[str], Dict[str, JsonValue]]:

        """This function returns inputs and arguments from arguments."""

        inputs = []

        for i, argument in enumerate(arguments):
            if argument["input"]:
                inputs.append(argument)

        for i, input_ in enumerate(inputs):
            arguments.remove(input_)
            inputs[i] = str(input_["value"])

        for i, argument in enumerate(arguments):
            arguments[i] = argument["value"]

        return inputs, arguments

    @log_trace
    def parse_body(self, environ: _Environ) -> Tuple[Content, str, bool]:

        """This function return arguments from body."""

        content_length = environ.get("CONTENT_LENGTH", "0")

        if content_length.isdigit():
            content_length = int(content_length)
        else:
            content_length = 0

        body = environ["wsgi.input"].read(content_length)

        if content_length:
            try:
                body = json.loads(body)
            except (json.decoder.JSONDecodeError, UnicodeDecodeError):
                Logs.warning("Non-JSON content detected")
                Logs.info(
                    "This request is not available for"
                    " the default functions of WebScripts"
                )
                return body, None, False

            if "arguments" in body.keys():
                arguments = []
                for name, argument in body["arguments"].items():
                    arguments += Argument.get_command(name, argument)

                return arguments, body.get("csrf_token"), True

            Logs.warning(
                'Section "arguments" is not defined in the JSON content.'
            )
            Logs.info(
                "This request is not available for"
                " the default functions of WebScripts"
            )
            return body, None, False

        return [], None, True

    @log_trace
    def app(self, environ: _Environ, respond: FunctionType) -> List[bytes]:

        """This function get function page,
        return content page, catch errors and
        return HTTP errors."""

        Logs.debug(
            f"Request ({environ['REQUEST_METHOD']}) from "
            f"{get_ip(environ)} on {environ['PATH_INFO']}."
        )

        get_response, filename, is_not_package = self.get_function_page(
            environ["PATH_INFO"]
        )

        user, not_blacklisted = self.check_auth(environ)

        if not not_blacklisted:
            Logs.critical(
                f'Blacklist: Error 403 on "{environ["PATH_INFO"]}" for '
                f'"{user.name}" (ID: {user.id}).'
            )
            return self.page_403(None, respond)

        arguments, csrf_token, is_webscripts_request = self.parse_body(environ)

        if is_webscripts_request:
            inputs, arguments = self.get_inputs(arguments)
        else:
            inputs = []

        if is_not_package and not is_webscripts_request:
            Logs.error(
                f'HTTP 406: for "{user.name}" on "{environ["PATH_INFO"]}"'
            )
            error = "406"
        else:
            error: str = None

        if (
            (
                (not self.configuration.accept_unknow_user and user.id == 1)
                or (
                    not self.configuration.accept_unauthenticated_user
                    and user.id == 0
                )
            )
            and self.configuration.active_auth
        ) and (
            environ["PATH_INFO"] not in self.configuration.exclude_auth_pages
            and not any(
                environ["PATH_INFO"].startswith(x)
                for x in self.configuration.exclude_auth_paths
            )
        ):
            self.send_headers(respond, "302 Found", {"Location": "/web/auth/"})
            return [
                b"Authentication required:\n\t",
                b" - For API you can use Basic Auth",
                b"\n\t - For API you can use Api-Key",
                b"\n\t - For Web Interface (with Web Browser) use /web/auth/",
            ]

        if get_response is None:
            return self.page_404(environ["PATH_INFO"], respond)

        if error == "406":
            return self.page_406(None, respond)

        try:
            error, headers, page = get_response(
                environ,
                user,
                self.configuration,
                filename,
                arguments,
                inputs,
                csrf_token=csrf_token,
            )
        except Exception as error:
            traceback.print_exc()
            error = f"{error}\n{traceback.format_exc()}"
            Logs.error(error)
            return self.page_500(traceback.format_exc(), respond)

        if error == "404":
            return self.page_404(environ["PATH_INFO"], respond)
        elif error == "403":
            return self.page_403(None, respond)
        elif error == "500":
            return self.page_500(page, respond)
        else:
            response = self.send_custom_error("", error)
            if response is not None:
                error, headers, page = response

        if not error:
            error = "200 OK"

        default_headers = self.headers.copy()
        default_headers.update(headers)

        self.send_headers(respond, error, default_headers)

        if isinstance(page, bytes):
            return [page]
        elif isinstance(page, str):
            return [page.encode()]
        elif isinstance(page, list):
            return page

    @log_trace
    def send_headers(
        self,
        respond: FunctionType,
        error: str = None,
        headers: Dict[str, str] = None,
    ) -> None:

        """This function send error code, message and headers."""

        if error is None:
            error = self.error
        if headers is None:
            _headers = self.headers
        else:
            _headers = self.headers.copy()
            _headers.update(headers)

        respond(error, [(k, v) for k, v in _headers.items()])

    @log_trace
    def page_500(self, error: str, respond: FunctionType) -> List[bytes]:

        """This function return error 500 web page."""

        error_code = "500 Internal Error"
        return self.send_error_page(error_code, error.encode(), respond)

    @log_trace
    def page_404(self, url: str, respond: FunctionType):

        """This function return error 404 web page."""

        error_code = "404 Not Found"
        urls = "\n\t - ".join(self.get_URLs())
        error = (
            f"This URL: {url}, doesn't exist"
            f" on this server.\nURLs:\n\t - {urls}"
        )
        Logs.error(f"HTTP 404 on {url}")
        return self.send_error_page(error_code, error.encode(), respond)

    @log_trace
    def page_401(self, error_description: str, respond: FunctionType):

        """This function return error 401 web page."""

        error_code = "401 Unauthorized"
        error = b"Unauthorized (You don't have permissions)"
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def page_403(self, error_description: str, respond: FunctionType):

        """This function return error 403 web page."""

        error_code = "403 Forbidden"
        error = b"Forbidden (You don't have permissions)"
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def page_406(self, error_description: str, respond: FunctionType):

        """This function return error 406 web page."""

        error_code = "406 Not Acceptable"
        error = (
            b"Not Acceptable, your request is not a valid WebScripts request."
        )
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def send_error_page(
        self, error: str, data: bytes, respond: FunctionType
    ) -> List[bytes]:

        """This function send HTTP errors."""

        code = error[:3]
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        error_ = ""

        try:
            custom_error, custom_headers, custom_data = self.send_custom_error(
                error, code
            )
        except Exception as exception:
            traceback.print_exc()
            error_ = f"{exception}\n{traceback.format_exc()}"
            Logs.error(error_)
            custom_data = None

        if self.debug:
            self.send_headers(respond, error, headers)
            return [
                b"---------------\n",
                f"** ERROR {code} **\n".encode(),
                b"---------------\n",
                b"\n\n",
                data,
                error_.encode(),
            ]

        if custom_data is not None:
            self.send_headers(respond, custom_error, custom_headers)
            return custom_data

        self.send_headers(respond, error, headers)
        return [
            b"---------------\n",
            f"** ERROR {code} **\n".encode(),
            b"---------------\n",
        ]

    def send_custom_error(
        self, error: str, code: str
    ) -> Tuple[str, Dict[str, str], str]:

        """This function call custom errors pages."""

        for package in self.pages.packages.__dict__.values():
            if isinstance(package, ModuleType):
                page = package.__dict__.get("page_" + code)
                if page is not None:
                    return page(
                        error,
                    )


@log_trace
def parse_args() -> Namespace:

    """This function parse command line arguments."""

    parser = ArgumentParser(
        description="This package implements a web server to run scripts or "
        "executables from the command line and display the result "
        "in a web interface.",
    )
    parser.add_argument(
        "-i", "--interface", help="Interface to launch WebScripts server."
    )
    parser.add_argument(
        "-p", "--port", help="Port to launch WebScripts server.", type=int
    )

    parser.add_argument(
        "-c",
        "--config-cfg",
        help="Config filename (syntax config,ini).",
        action="extend",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-j",
        "--config-json",
        help="Config filename (syntax json).",
        action="extend",
        nargs="+",
        default=[],
    )

    dev = parser.add_argument_group(
        "DEV",
        "Arguments for development and debugging [do NOT use these arguments "
        "in production !]",
    )
    dev.add_argument(
        "-d",
        "--debug",
        help="Debug (to get errors details).",
        action="store_true",
        default=None,
    )
    dev.add_argument(
        "-s",
        "--security",
        help="Remove HTTP security headers [Disable security],"
        " active the Content-Security-Policy-Report-Only header"
        ' and the CSP debug module (URL: "/csp/debug/")',
        action="store_false",
        default=None,
    )

    auth = parser.add_argument_group("AUTH", "authentication configurations")
    auth.add_argument(
        "-a",
        "--active-auth",
        help="Disable authentication page [Disable auth (force to accept "
        "unknow and unauthenticated user)].",
        action="store_false",
        default=None,
    )
    auth.add_argument("--auth-script", help="Script for authentication.")
    auth.add_argument(
        "--accept-unauthenticated-user",
        help="Accept unauthenticated user.",
        action="store_true",
        default=None,
    )
    auth.add_argument(
        "--accept-unknow-user",
        help="Accept unknow user.",
        action="store_true",
        default=None,
    )
    auth.add_argument(
        "-b",
        "--auth-failures-to-blacklist",
        type=int,
        help="Number of authentication failures to blacklist an IP or user.",
    )
    auth.add_argument(
        "-B",
        "--blacklist-time",
        type=int,
        help="Time (in seconds) to blacklist an IP or user.",
    )
    auth.add_argument(
        "--e-auth-paths",
        "--exclude-auth-paths",
        action="extend",
        nargs="+",
        default=[],
        help="Start of paths where the unauthenticated user gets access.",
    )
    auth.add_argument(
        "--e-auth-pages",
        "--exclude-auth-pages",
        action="extend",
        nargs="+",
        default=[],
        help="Specific page where the unauthenticated user has access.",
    )

    parser.add_argument(
        "-S",
        "--scripts-path",
        help="Add directory to search scripts",
        action="extend",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-C",
        "--scripts-config",
        help="Add file for scripts configuration (glob syntax)",
        action="extend",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-m",
        "--modules",
        help="Add modules to add urls.",
        nargs="+",
        action="extend",
        default=[],
    )
    parser.add_argument(
        "-I",
        "--modules-path",
        help="Add directory to search modules/packages",
        action="extend",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-D",
        "--documentations-path",
        help="Add directory to search documentations",
        action="extend",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-J",
        "--js-path",
        help="Add directory to get Javascript files.",
        action="extend",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-T",
        "--statics-path",
        help="Add directory to get static files",
        action="extend",
        nargs="+",
        default=[],
    )

    logs = parser.add_argument_group("LOGS", "logs configurations")
    logs.add_argument(
        "-l",
        "--log-level",
        help="Log level for ROOT logger.",
        choices=["0", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    logs.add_argument(
        "-f", "--log-filename", help="Log filename for ROOT logger."
    )
    logs.add_argument("--log-format", help="Format for ROOT logger.")
    logs.add_argument("--log-date-format", help="Date format for ROOT logger.")
    logs.add_argument("--log-encoding", help="Encoding for ROOT logger.")

    smtp = parser.add_argument_group(
        "SMTP", "SMTP configurations to send email notifications"
    )
    smtp.add_argument(
        "--smtp-server",
        "--s-server",
        help="The SMTP server to use to send email notification.",
    )
    smtp.add_argument(
        "--smtp-starttls",
        "--s-tls",
        help="Use STARTTLS to secure the connection.",
        action="store_true",
        default=None,
    )
    smtp.add_argument(
        "--smtp-password",
        "--s-password",
        help="The SMTP password to login the notification account.",
    )
    smtp.add_argument(
        "--smtp-port",
        "--s-port",
        help="The SMTP port to use to send email notification.",
        type=int,
    )
    smtp.add_argument(
        "--smtp-ssl",
        "--s-ssl",
        help="Use SSL to secure the connection",
        action="store_true",
        default=None,
    )
    smtp.add_argument(
        "--admin-adresses",
        "--a-adr",
        help="The admintrators email addresses to receive the email "
        "notifications.",
        nargs="+",
        action="extend",
    )
    smtp.add_argument(
        "--notification-address",
        "--n-adr",
        help="The email address to send notifications.",
    )
    return parser.parse_args()


@log_trace
def get_server_config(arguments: Namespace) -> Iterator[dict]:

    """This generator return configurations dict."""

    current_directory = getcwd()

    paths = [
        path.join(current_directory, "config", "server.ini"),
        path.join(current_directory, "config", "server.json"),
    ]
    if platform.system() == "Windows":
        paths.insert(0, path.join(server_path, "config", "nt", "server.json"))
        paths.insert(0, path.join(server_path, "config", "nt", "server.ini"))
    else:
        paths.insert(0, path.join(server_path, "config", "server.json"))
        paths.insert(0, path.join(server_path, "config", "server.ini"))

    for filename in paths:
        Logs.warning(f"Configuration file detection: {filename}")

        if path.exists(filename):
            if filename.endswith(".json"):
                yield json.loads(get_file_content(filename))
            elif filename.endswith(".ini"):
                yield get_ini_dict(filename)
        else:
            Logs.error(f"Configuration named {filename} doesn't exists.")

    for filename in arguments.config_cfg:
        Logs.warning(f"Configuration file detection (type cfg): {filename}")

        if path.exists(filename):
            yield get_ini_dict(filename)
        else:
            Logs.error(f"Configuration named {filename} doesn't exists.")

    for filename in arguments.config_json:
        Logs.warning(f"Configuration file detection (type json): {filename}")

        if path.exists(filename):
            yield json.loads(get_file_content(filename))
        else:
            Logs.error(f"Configuration named {filename} doesn't exists.")

    args = arguments.__dict__
    del args["config_cfg"]
    del args["config_json"]

    yield {k: v for k, v in args.items() if v is not None}


@log_trace
def logs_configuration(configuration: NameSpace) -> None:

    """This function configure ROOT logger from
    configuration files and command line arguments."""

    log_config = {}

    if isinstance(configuration.log_level, int):
        pass
    elif (
        isinstance(configuration.log_level, str)
        and configuration.log_level.isdigit()
    ):
        configuration.log_level = int(configuration.log_level)
    elif isinstance(configuration.log_level, str):
        configuration.log_level = getattr(logging, configuration.log_level, 0)
    else:
        raise WebScriptsConfigurationError(
            "log_level configuration must be an integer or a "
            'string in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]'
        )

    for attr, item in {
        "log_format": "format",
        "log_date_format": "datefmt",
        "log_encoding": "encoding",
        "log_level": "level",
        "log_filename": "filename",
    }.items():
        value = getattr(configuration, attr, None)
        if value is not None:
            log_config[item] = value

    if log_config:
        log_config["force"] = True
        Logs.config(**log_config)


@log_trace
def add_configuration(
    configuration: Configuration, config: Dict[str, JsonValue]
) -> Configuration:

    """This function add configuration in ServerConfiguration."""

    current_configuration = Configuration()
    have_server_conf = "server" in config.keys()

    if have_server_conf:
        server = config.pop("server")

    current_configuration.add_conf(**config)

    if have_server_conf:
        current_configuration.add_conf(**server)

    current_configuration.build_types()

    Logs.debug(
        "Add configurations in ServerConfiguration: "
        f"{current_configuration.get_dict()}"
    )
    configuration.add_conf(**current_configuration.get_dict())
    return configuration


def configure_logs_system() -> None:

    """This function try to create the logs directory
    if not found and configure logs."""

    if not path.isdir("logs"):
        Logs.info("./logs directory not found.")
        try:
            mkdir("logs")
        except PermissionError:
            Logs.error(
                "Get a PermissionError to create "
                "the non-existent ./logs directory."
            )
        else:
            Logs.info("./logs directory is created.")

    logging.config.fileConfig(
        path.join(server_path, "config", "loggers.ini"),
        disable_existing_loggers=False,
    )

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s (%(funcName)s -> "
        "%(filename)s:%(lineno)d)",
        datefmt="%d/%m/%Y %H:%M:%S",
        encoding="utf-8",
        level=0,
        filename="./logs/root.logs",
        force=True,
    )

    # for logger in (
    #     "log_trace",
    #     "log_debug",
    #     "log_info",
    #     "log_warning",
    #     "log_error",
    #     "log_critical",
    #     "file",
    # ):
    #     logger = getattr(Logs, logger)

    #     if logger.hasHandlers() and len(logger.handlers):
    #         logger.handlers[0].doRollover = Handler.doRollover
    #         logger.handlers[0].rotator = Handler.rotator
    #         logger.handlers[0].namer = Handler.namer


def send_mail(configuration: Configuration, message: str) -> int:

    """This function send a mail to adminitrators
    using the error_pages modules.

    Return 0 if message is sent else 1."""

    error_pages = getattr(Pages.packages, "error_pages", None)
    if error_pages:
        Thread(
            target=error_pages.Request.send_mail,
            args=(
                configuration,
                message,
            ),
        ).start()
        return 0

    return 1


def main() -> int:

    """
    Main function to build the
    configurations and launch the server.
    """

    if "--test-running" in sys.argv:
        NO_START = True
        sys.argv.remove("--test-running")
    else:
        NO_START = False

    configure_logs_system()
    args = parse_args()

    Logs.debug("Load configuration...")

    configuration = Configuration()
    for config in get_server_config(args):
        configuration = add_configuration(configuration, config)

    configuration = add_configuration(configuration, args.__dict__)

    logs_configuration(configuration)

    Logs.debug("Check configuration...")
    configuration.set_defaults()
    configuration.check_required()
    configuration.get_unexpecteds()
    configuration.build_types()

    if getattr(configuration, "debug", None):
        configuration.export_as_json()

    Logs.debug("Build server from configuration...")
    server = Server(configuration)

    httpd = simple_server.make_server(
        server.interface, server.port, server.app
    )

    send_mail(
        configuration,
        f"Server is up on http://{server.interface}:{server.port}/.",
    )
    hardening(server, Logs, send_mail)

    Logs.warning(
        f"Starting server on http://{server.interface}:{server.port}/ ..."
    )
    print(copyright)

    if NO_START:
        return 0

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        Logs.critical("Server is down.")
        httpd.server_close()

    send_mail(
        configuration,
        f"Server is down on http://{server.interface}:{server.port}/.",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
