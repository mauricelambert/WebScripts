#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a web server to run scripts or executables
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

"""This package implements a web server to run scripts or 
executables from the command line and display the result 
in a web interface.

This file is the "main" file of this package (implement the main function,
the Server class and the Configuration class)."""

from types import SimpleNamespace, ModuleType, FunctionType
from collections.abc import Iterator, Callable
from argparse import Namespace, ArgumentParser
from typing import TypeVar, Tuple, List, Dict
from os import path, _Environ, getcwd
from wsgiref import simple_server
from base64 import b64decode
from glob import iglob
import traceback
import logging
import json
import sys


if __package__:
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
        #        get_real_path,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )
else:
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
        #        get_real_path,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )

__version__ = "0.0.3"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file is the "main" file of this package (implement the main function,
the Server class and the Configuration class)."""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = ["Configuration", "Server", "main"]

NameSpace = TypeVar("NameSpace", SimpleNamespace, Namespace)
FunctionOrNone = TypeVar("FunctionOrNone", FunctionType, None)


class Configuration(DefaultNamespace):

    """This class build the configuration from dict(s) with
    configuration files and arguments."""

    __defaults__ = {
        "interface": "127.0.0.1",
        "port": 8000,
        "modules": [],
        "js_path": [],
        "statics_path": [],
        "scripts_path": [],
        "modules_path": [],
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
                            f"Configuration list {key}: {value} can't be add to {default_value}"
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

        self.headers = {
            "Server": f"WebScripts {__version__}",
            "Content-Type": "text/html; charset=utf-8",
        }

        self.debug = getattr(configuration, "debug", False)
        self.security = getattr(configuration, "security", True)
        self.loglevel = getattr(configuration, "log_level", "DEBUG")

        if self.security:
            self.headers[
                "Strict-Transport-Security"
            ] = "max-age=63072000; includeSubDomains; preload"
            self.headers[
                "Content-Security-Policy"
            ] = "default-src 'self'; form-action 'none'"
            self.headers["X-Frame-Options"] = "deny"
            self.headers["X-XSS-Protection"] = "1; mode=block"
            self.headers["X-Content-Type-Options"] = "nosniff"
            self.headers["Referrer-Policy"] = "origin-when-cross-origin"
            self.headers["Cache-Control"] = "no-store"
            self.headers["Clear-Site-Data"] = "*"
            self.headers["Feature-Policy"] = "microphone 'none'; camera 'none'"
            self.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
            self.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            self.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        else:
            self.headers[
                "Content-Security-Policy-Report-Only"
            ] = "default-src 'self'; form-action 'none'"

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
                    f"User {name} is blacklisted ({user.counter} attempt using IP {ip})"
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
                user = Session.check_session(cookie, self.pages, ip, None)

                if user is None:
                    continue

                if ip != user.ip:
                    user = User.default_build(ip=ip, check_csrf=True, **self.unknow)
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
            credentials = b64decode(credentials.split(" ", maxsplit=1)[1]).decode()

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
            user = Session.check_session(cookie, self.pages, ip, None)

        not_blacklisted = self.check_blacklist(user, ip)
        if user is not None and not_blacklisted:
            return user, not_blacklisted

        if user is None:
            return User.default_build(ip=ip, **self.not_authenticated), not_blacklisted
        else:
            return User.default_build(ip=ip, **self.unknow), not_blacklisted

    @log_trace
    def add_module_or_package(self) -> None:

        """This function add packages and modules to build custom page."""

        sys.path = self.configuration.modules_path + sys.path

        Pages.packages = DefaultNamespace()
        for package in self.configuration.modules:
            Logs.warning(f"Add package/module named: {package}")

            package = __import__(package)
            setattr(Pages.packages, package.__name__, package)

        for path_ in self.configuration.modules_path:
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

                    Pages.js_paths[filename] = CallableFile("js", file_path, filename)

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
    def get_function_page(self, path: str) -> FunctionOrNone:

        """This function find function from URL path."""

        path = path.split("/")
        del path[0]

        default, filename = self.get_attributes(self.pages, path)

        if default is not None:
            return default, filename
        else:
            return self.get_attributes(self.pages.packages, path)

    @log_trace
    def get_URLs(self) -> List[str]:

        """This function return a list of string."""

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
        self, object_: object, attributes: List[str]
    ) -> Tuple[FunctionOrNone, str]:

        """This function get recursive attribute from object."""

        for attribute in attributes[:-1]:
            # attribute = capwords(attribute)
            object_ = getattr(object_, attribute, None)

            if object_ is None:
                return None, None

        if isinstance(object_, Callable):
            return object_, attributes[-1]
        else:
            return None, None

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
    def parse_body(self, environ: _Environ) -> Tuple[List[Dict[str, JsonValue]], str]:

        """This function return arguments from body."""

        content_length = environ.get("CONTENT_LENGTH", "0")

        if content_length.isdigit():
            content_length = int(content_length)
        else:
            content_length = 0

        body = environ["wsgi.input"].read(content_length)

        if content_length:
            body = json.loads(body)

            arguments = []
            for name, argument in body["arguments"].items():
                arguments += Argument.get_command(name, argument)

            return arguments, body.get("csrf_token")

        return [], None

    @log_trace
    def app(self, environ: _Environ, respond: FunctionType) -> List[bytes]:

        """This function get function page,
        return content page, catch errors and
        return HTTP errors."""

        Logs.debug(
            f"Request ({environ['REQUEST_METHOD']}) from {get_ip(environ)} on {environ['PATH_INFO']}."
        )

        get_response, filename = self.get_function_page(environ["PATH_INFO"])

        user, not_blacklisted = self.check_auth(environ)

        if not not_blacklisted:
            Logs.critical(
                f'Blacklist: Error 403 on "{environ["PATH_INFO"]}" for "{user.name}" (ID: {user.id}).'
            )
            return self.page_403(None, respond)

        arguments, csrf_token = self.parse_body(environ)
        inputs, arguments = self.get_inputs(arguments)
        error: str = None

        if (
            (
                (not self.configuration.accept_unknow_user and user.id == 1)
                or (not self.configuration.accept_unauthenticated_user and user.id == 0)
            )
            and self.configuration.active_auth
        ) and (
            environ["PATH_INFO"] != "/auth/"
            and environ["PATH_INFO"] != "/web/auth/"
            and environ["PATH_INFO"] != "/api/"
            and not environ["PATH_INFO"].startswith("/js/")
            and not environ["PATH_INFO"].startswith("/static/")
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

        if not error:
            error = "200 OK"

        default_headers = self.headers.copy()
        default_headers.update(headers)

        self.send_headers(respond, error, default_headers)

        if isinstance(page, bytes):
            return [page]
        elif isinstance(page, str):
            return [page.encode()]

    @log_trace
    def send_headers(
        self, respond: FunctionType, error: str = None, headers: Dict[str, str] = None
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
        error = f"This URL: {url}, doesn't exist on this server.\nURLs:\n\t - {urls}"
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

    parser = ArgumentParser()
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
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-j",
        "--config-json",
        help="Config filename (syntax json).",
        nargs="+",
        default=[],
    )

    parser.add_argument(
        "-d",
        "--debug",
        help="Debug (to get errors details).",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "-s",
        "--security",
        help="Remove HTTP security headers [Disable security].",
        action="store_false",
        default=None,
    )
    parser.add_argument(
        "-a",
        "--active-auth",
        help="Disable authentication page [Disable auth (force to accept unknow and unauthenticated user)].",
        action="store_false",
        default=None,
    )
    parser.add_argument("--auth-script", help="Script for authentication.")
    parser.add_argument(
        "--accept-unauthenticated-user",
        help="Accept unauthenticated user.",
        action="store_true",
        default=None,
    )
    parser.add_argument(
        "--accept-unknow-user",
        help="Accept unknow user.",
        action="store_true",
        default=None,
    )

    parser.add_argument(
        "-S",
        "--scripts-path",
        help="Add directory to search scripts",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-C",
        "--scripts-config",
        help="Add file for scripts configuration (glob syntax)",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-m", "--modules", help="Add modules to add urls.", nargs="+", default=[]
    )
    parser.add_argument(
        "-I",
        "--modules-path",
        help="Add directory to search modules/packages",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-D",
        "--documentations-path",
        help="Add directory to search documentations",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-J",
        "--js-path",
        help="Add directory to get Javascript files.",
        nargs="+",
        default=[],
    )
    parser.add_argument(
        "-T",
        "--statics-path",
        help="Add directory to get static files",
        nargs="+",
        default=[],
    )

    parser.add_argument(
        "-l",
        "--log-level",
        help="Log level for ROOT logger.",
        choices=["0", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument("-f", "--log-filename", help="Log filename for ROOT logger.")
    parser.add_argument("--log-format", help="Format for ROOT logger.")
    parser.add_argument("--log-date-format", help="Date format for ROOT logger.")
    parser.add_argument("--log-encoding", help="Encoding for ROOT logger.")
    parser.add_argument(
        "-b",
        "--auth-failures-to-blacklist",
        type=int,
        help="Number of authentication failures to blacklist an IP or user.",
    )
    parser.add_argument(
        "-B",
        "--blacklist-time",
        type=int,
        help="Time (in seconds) to blacklist an IP or user.",
    )
    return parser.parse_args()


@log_trace
def get_server_config(arguments: Namespace) -> Iterator[dict]:

    """This generator return configurations dict."""

    current_directory = getcwd()

    config_files = (
        path.join("config", "server.ini"),
        path.join("config", "server.json"),
    )

    for dirname in (server_path, current_directory):
        for filename in config_files:

            _path = path.join(dirname, filename)
            Logs.warning(f"Configuration file detection: {_path}")

            if path.exists(_path):
                if ".json" in filename:
                    yield json.loads(get_file_content(_path))
                elif ".ini" in filename:
                    yield get_ini_dict(filename)
            else:
                Logs.error(f"Configuration named {_path} doesn't exists.")

    for filename in arguments.config_cfg:
        Logs.warning(f"Configuration file detection (type cfg): {filename}")

        if path.exists(filename):
            yield get_ini_dict(filename)
        else:
            Logs.error(f"Configuration named {filename} doesn't exists.")

    for filename in arguments.config_json:
        Logs.warning(f"Configuration file detection (type json): {filename}")

        if path.exists(filename):
            yield json.loads(_path)
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

    if configuration.log_level == "0":
        configuration.log_level = 0
    else:
        configuration.log_level = getattr(logging, configuration.log_level, 0)

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
        f"Add configurations in ServerConfiguration: {current_configuration.get_dict()}"
    )
    configuration.add_conf(**current_configuration.get_dict())
    return configuration


def main() -> None:

    """Main function to launch server, get configuration and logs."""

    logging.config.fileConfig(
        path.join(server_path, "config", "loggers.ini"),
        disable_existing_loggers=False,
    )
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s (%(funcName)s -> %(filename)s:%(lineno)d)",
        datefmt="%d/%m/%Y %H:%M:%S",
        encoding="utf-8",
        level=0,
        filename="./logs/root.logs",
        force=True,
    )

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

    httpd = simple_server.make_server(server.interface, server.port, server.app)

    Logs.warning(f"Starting server on http://{server.interface}:{server.port}/ ...")
    print(copyright)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        Logs.critical("Server is down.")
        httpd.server_close()

    sys.exit(0)


if __name__ == "__main__":
    main()
