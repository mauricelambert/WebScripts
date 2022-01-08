#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tools run scripts and display the result in a Web Interface.
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

"""This tools run scripts and display the result in a Web Interface.

This file is the "main" file of this package (implement the main function,
the Server class and the Configuration class)."""

__version__ = "0.1.2"
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
WebScripts  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Configuration", "Server", "main"]

from os.path import basename, abspath, join, dirname, normcase, exists, isdir
from types import SimpleNamespace, ModuleType, FunctionType
from typing import TypeVar, Tuple, List, Dict, Union
from sys import exit, modules as sys_modules, argv
from collections.abc import Iterator, Callable
from argparse import Namespace, ArgumentParser
from traceback import print_exc, format_exc
from json.decoder import JSONDecodeError
from os import _Environ, getcwd, mkdir
from logging.config import fileConfig
from wsgiref import simple_server
from logging import basicConfig
from threading import Thread
from base64 import b64decode
from platform import system
from json import loads
from glob import iglob
import logging
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
        WebScriptsArgumentError,
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
        WebScriptsArgumentError,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )

NameSpace = TypeVar("NameSpace", SimpleNamespace, Namespace)
FunctionOrNone = TypeVar("FunctionOrNone", FunctionType, None)
Content = TypeVar(
    "Content", List[Dict[str, JsonValue]], Dict[str, JsonValue], bytes
)

logger_debug: Callable = Logs.debug
logger_info: Callable = Logs.info
logger_warning: Callable = Logs.warning
logger_error: Callable = Logs.error
logger_critical: Callable = Logs.critical
current_directory: str = getcwd()
log_path: str = join(current_directory, "logs")


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

        """
        Add configurations from other configuration files found.
        """

        logger_info("Add configurations...")

        for key, value in kwargs.items():

            if value is not None:
                dict_ = self.__dict__

                logger_info(f"Add configuration {key}: {value}")
                default_value = dict_.get(key)

                if isinstance(default_value, list):

                    if isinstance(value, str):
                        logger_debug(
                            "Add configuration list " "using INI/CFG syntax."
                        )
                        value = value.split(",")

                    if isinstance(value, list):
                        logger_debug(
                            "Add configuration list " "using JSON syntax."
                        )
                        for value_ in value:
                            if value_ not in dict_[key]:
                                dict_[key].append(value_)
                    else:
                        logger_error(
                            "Error in configuration: "
                            "list should be a JSON list"
                            " or INI/CFG comma separated string."
                            f" (not: {value})"
                        )
                        raise WebScriptsConfigurationTypeError(
                            f"Configuration list {key}: {value} can't be "
                            f"add to {default_value}"
                        )

                elif isinstance(default_value, dict):
                    logger_debug(f"Add configuration dict... {key}={value}")
                    dict_[key].update(value)
                else:
                    logger_debug(f'Add "basic" configuration {key}={value}.')
                    dict_[key] = value


class Server:

    """This class implement the WebScripts server."""

    @log_trace
    def __init__(self, configuration: Configuration):
        self.configuration = configuration
        self.interface: str = configuration.interface
        self.port: int = configuration.port

        logger_debug("Create default value for WebScripts server...")
        # self.user: Dict[str, User] = {}
        self.unknow: Dict = {"id": 1, "name": "Unknow", "groups": [0, 1]}
        self.not_authenticated: Dict = {
            "id": 0,
            "name": "Not Authenticated",
            "groups": [0],
        }
        self.error: str = "200 OK"
        self.pages = Pages()
        self.logs = Logs

        version = self.version = (
            sys_modules[__package__].__version__
            if __package__
            else __version__
        )

        logger_debug("Create default HTTP headers...")
        headers = self.headers = {
            "Server": f"WebScripts {version}",
            "Content-Type": "text/html; charset=utf-8",
        }

        logger_debug("Get security configuration...")
        self.debug = getattr(configuration, "debug", False)
        security = self.security = getattr(configuration, "security", True)
        self.loglevel = getattr(configuration, "log_level", "DEBUG")

        self.set_default_headers(headers, security, configuration)
        self.add_module_or_package()
        self.add_paths()

    @staticmethod
    @log_trace
    def set_default_headers(
        headers: Dict[str, str], security: bool, configuration: Configuration
    ) -> None:

        """
        This function sets defaults headers.
        """

        logger_debug("Set defaults headers...")

        if security:
            headers[
                "Strict-Transport-Security"
            ] = "max-age=63072000; includeSubDomains; preload"
            headers["Content-Security-Policy"] = (
                "default-src 'self'; form-action 'none'; "
                "frame-ancestors 'none'"
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
        else:
            logger_warning(
                "Load insecure HTTP headers for development environment..."
            )
            if "csp" not in configuration.modules:
                configuration.modules.append("csp")
            if "modules" not in configuration.modules_path:
                configuration.modules_path.append("modules")
            if "/csp/debug/" not in configuration.exclude_auth_pages:
                configuration.exclude_auth_pages.append("/csp/debug/")

            headers["Content-Security-Policy-Report-Only"] = (
                "default-src 'self'; form-action 'none'; "
                "frame-ancestors 'none'; report-uri /csp/debug/"
            )

        logger_info("Default HTTP headers are set.")

    @log_trace
    def check_blacklist(self, user: User, ip: str) -> bool:

        """
        This function checks that the IP and the
        username are not in the blacklist.
        """

        logger_debug("Check blacklist...")

        pages = self.pages
        configuration = self.configuration

        logger_debug("Check user blacklist...")
        if user is not None:
            name = user.name
            user = pages.user_blacklist.get(user.id, None)
            if user is not None and user.is_blacklist(configuration):
                logger_critical(
                    f"User {name} is blacklisted "
                    f"({user.counter} attempt using IP {ip})"
                )
                return False

        logger_debug("Check ip blacklist...")
        ip_ = pages.ip_blacklist.get(ip, None)
        if ip_ is not None and ip_.is_blacklist(configuration):
            logger_critical(f"IP {ip} is blacklisted ({ip_.counter} attempt).")
            return False

        logger_info("IP and user not blacklisted.")
        return True

    @log_trace
    def get_session(self, cookies: List[str], ip: str) -> User:

        """
        This function return User from cookies.
        """

        for cookie in cookies:
            logger_debug("Analyze a new cookie...")

            if cookie.startswith("SessionID="):
                logger_debug("Session cookie is detected...")
                user = Session.check_session(
                    cookie,
                    self.pages,
                    ip,
                    None,
                    getattr(self.configuration, "session_max_time", 3600),
                )

                if user is None:
                    logger_warning("Session cookie is not valid.")
                    continue

                if ip != user.ip:
                    logger_warning("Session IP is not valid.")
                    user = User.default_build(
                        ip=ip, check_csrf=True, **self.unknow
                    )
                else:
                    logger_info("Valid session detected.")
                    user.check_csrf = True

                return user

    @staticmethod
    @log_trace
    def use_basic_auth(
        credentials: str, pages: Pages, *args
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function decodes basic auth and
        authenticates user with it.
        """

        logger_debug("Basic Auth detected, decode credentials...")
        credentials = b64decode(credentials.split(" ", maxsplit=1)[1]).decode()

        if ":" in credentials:
            username, password = credentials.split(":", maxsplit=1)

            logger_info("Use authentication script...")
            return pages.auth(
                *args,
                ["--username", username, "--password", password],
                [],
            )

        logger_error(
            "Basic auth detected with invalid "
            "credentials (':' not in credentials)."
        )

    @log_trace
    def check_auth(self, environ: _Environ) -> Tuple[User, bool]:

        """
        This function check if user is authenticated and blacklisted.
        """

        environ_get = environ.get
        logger_debug("Check auth...")
        credentials = environ_get("HTTP_AUTHORIZATION")
        api_key = environ_get("HTTP_API_KEY")
        cookies = environ_get("HTTP_COOKIE")
        token = environ_get("HTTP_API_TOKEN")
        ip = get_ip(environ)

        pages = self.pages
        configuration = self.configuration
        not_authenticated = self.not_authenticated
        check_session = Session.check_session
        default_build = User.default_build

        user = None
        headers = None

        if cookies is not None:
            logger_debug("Cookie detected, try to get session...")
            user = self.get_session(cookies.split("; "), ip)

        elif token is not None:
            logger_debug("API token detected, try to get session...")
            user = check_session(
                token.split(";")[0],
                pages,
                ip,
                None,
                getattr(configuration, "session_max_time", 3600),
            )

        if (
            user is None
            and credentials is not None
            and credentials.startswith("Basic ")
        ):
            auth = self.use_basic_auth(
                credentials,
                pages,
                environ,
                default_build(ip=ip, **not_authenticated),
                configuration,
                configuration.auth_script,
            )
            code, headers, content = (
                auth if auth is not None else (None, None, None)
            )

        elif api_key is not None:
            logger_info("API key detected. Use authentication script...")
            code, headers, content = pages.auth(
                environ,
                default_build(ip=ip, **not_authenticated),
                configuration,
                configuration.auth_script,
                ["--api-key", api_key],
                [],
            )

        if headers is not None:
            logger_debug("Get user using new cookie...")
            cookie = headers.get("Set-Cookie", "").split("; ")[0]
            user = check_session(
                cookie,
                pages,
                ip,
                None,
                getattr(configuration, "session_max_time", 3600),
            )

        logger_debug("Blacklist check...")
        not_blacklisted = self.check_blacklist(user, ip)

        if user is None:
            logger_info("No user [valid authentication] detected.")
            return (
                default_build(ip=ip, **not_authenticated),
                not_blacklisted,
            )
        else:
            logger_info("Authenticated user detected.")
            return user, not_blacklisted

    @log_trace
    def add_module_or_package(self) -> None:

        """This function add packages and modules to build custom page."""

        modules_path = []
        configuration = self.configuration
        append = modules_path.append
        logger_info("Load modules and packages...")

        for module_path in configuration.modules_path[::-1]:
            path2 = join(server_path, module_path)

            append(module_path)
            append(path2)
            logger_debug(
                f'Add "{module_path}" and "{path2}" in python path...'
            )

        sys.path = modules_path + sys.path

        packages = Pages.packages = DefaultNamespace()
        for package in configuration.modules:
            logger_warning(f"Add package/module named: {package}")

            package = __import__(package)
            setattr(packages, package.__name__, package)

        logger_info("Remove new paths...")
        for path_ in modules_path:
            logger_debug(f"Remove {path_}")
            sys.path.remove(path_)

    @log_trace
    def add_paths(self) -> None:

        """
        This function add js, static and scripts paths.
        """

        configuration = self.configuration
        statics_paths = Pages.statics_paths = {}
        js_paths = Pages.js_paths = {}

        logger_debug("Add scripts in Web pages...")
        scripts = (
            Pages.scripts
        ) = ScriptConfig.build_scripts_from_configuration(
            configuration,
        )
        logger_info("Scripts are in Web pages.")

        for dirname_ in (server_path, current_directory):
            logger_debug(f"Trying to find JS and static path in {dirname_}...")

            for globs, type_, type_name, dict_ in (
                (configuration.js_path, "js", "javascript", js_paths),
                (
                    configuration.statics_path,
                    "static",
                    "static",
                    statics_paths,
                ),
            ):

                for glob in globs:
                    glob = join(dirname_, normcase(glob))
                    logger_debug(
                        f"Trying to find file matching with {glob}..."
                    )
                    for file in iglob(glob):
                        filename = basename(file)
                        file_path = abspath(file)

                        Logs.info(f"Find a {type_name} file: {file_path}")

                        dict_[filename] = CallableFile(
                            type_, file_path, filename
                        )

        if (
            configuration.active_auth
            and configuration.auth_script not in scripts.keys()
        ):
            logger_error("Auth script not found in configurations.")
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
        get_attributes = self.get_attributes
        pages = self.pages

        logger_debug(
            "Trying to get function page from default WebScripts function..."
        )
        default, filename, _ = get_attributes(pages, path)

        if default is not None:
            logger_info("Use default function page.")
            return default, filename, True
        else:
            logger_debug("Trying to get function page from packages.")
            return get_attributes(pages.packages, path, False)

    @log_trace
    def get_URLs(self) -> List[str]:

        """
        This function return a list of urls (scripts, documentation...)
        and the start of the URL of custom packages.
        """

        urls = ["/api/", "/web/"]
        append = urls.append
        pages = self.pages

        if getattr(self.configuration, "active_auth", None):
            append("/auth/")
            append("/web/auth/")

        for script_name in pages.scripts.keys():
            append(f"/web/scripts/{script_name}")
            append(f"/api/scripts/{script_name}")
            append(f"/web/doc/{script_name}")

        for js_name in pages.js_paths.keys():
            append(f"/js/{js_name}")

        for static_name in pages.statics_paths.keys():
            append(f"/static/{static_name}")

        for package in dir(pages.packages):
            if isinstance(getattr(pages.packages, package), ModuleType):
                append(f"/{package}/...")

        return urls

    @staticmethod
    @log_trace
    def get_attributes(
        object_: object,
        attributes: List[str],
        is_not_package: bool = True,
    ) -> Tuple[FunctionOrNone, str, bool]:

        """
        This function get recursive attribute from object.
        """

        for attribute in attributes[:-1]:
            logger_debug(f"Trying to get {attribute} from {object_}")
            object_ = getattr(object_, attribute, None)

            if object_ is None:
                return None, None, is_not_package

        logger_debug("Get arguments length and check it...")
        arg_count = get_arguments_count(object_)

        if isinstance(object_, Callable) and (
            arg_count == 7 or arg_count == 8
        ):
            logger_info(f"Function page found {object_}.")
            return object_, attributes[-1], is_not_package
        else:
            logger_info("Function page not found.")
            return None, None, is_not_package

    @staticmethod
    @log_trace
    def get_inputs(
        arguments: List[Dict[str, JsonValue]]
    ) -> Tuple[List[str], List[str]]:

        """
        This function returns inputs and arguments from arguments.
        """

        inputs = []
        append = inputs.append
        remove = arguments.remove

        logger_debug("Extract inputs from WebScripts arguments...")
        for i, argument in enumerate(arguments):
            if argument["input"]:
                # logger_debug(f"Input found: {argument}")
                # To protect secrets, do not log arguments !
                append(argument)

        logger_debug("Remove inputs from arguments...")
        for i, input_ in enumerate(inputs):
            # logger_debug(f"Remove {input_}")
            # To protect secrets, do not log arguments !
            remove(input_)
            inputs[i] = str(input_["value"])

        logger_debug("Extract value from WebScripts arguments...")
        for i, argument in enumerate(arguments):
            arguments[i] = argument["value"]

        return inputs, arguments

    @staticmethod
    @log_trace
    def get_content_length(environ: _Environ) -> int:

        """
        This function returns the content length.
        """

        content_length = environ.get("CONTENT_LENGTH", "0")

        if content_length.isdigit():
            logger_debug(f"Content-Length is valid ({content_length}).")
            return int(content_length)
        else:
            logger_warning(f"Content-Length is not valid ({content_length}).")
            return 0

    @staticmethod
    @log_trace
    def try_get_command(
        body: Dict[str, JsonValue]
    ) -> Union[None, Tuple[Content, str, bool]]:

        """
        This function returns arguments, CSRF token and True if is WebScripts
        request. If is not a WebScripts request because there's no "arguments"
        section in request content, this function returns None. If an error
        is raised in arguments parser, this function returns the JSON
        content, None and False.
        """

        body_get = body.get
        arguments_ = body_get("arguments")
        get_command = Argument.get_command

        arguments = []

        if arguments_ is not None:
            logger_debug('"arguments" section detected in request content.')
            try:
                for name, argument in arguments_.items():
                    arguments += get_command(name, argument)
            except (WebScriptsArgumentError, TypeError, AttributeError):
                logger_error("Arguments detected is not in WebScripts format.")
                return body, None, False

            return arguments, body_get("csrf_token"), True

    @staticmethod
    @log_trace
    def get_baseurl(environ_getter: Callable, environ: _Environ) -> str:

        """
        This function returns URL base.
        """

        scheme = environ["wsgi.url_scheme"]
        port = environ["SERVER_PORT"]

        host = environ_getter("HTTP_HOST") or (
            environ["SERVER_NAME"]
            if (scheme == "https" and port == "443")
            or (scheme == "http" and port == "80")
            else f"{environ['SERVER_NAME']}:{port}"
        )
        return f"{scheme}://{host}"

    @staticmethod
    @log_trace
    def check_origin(environ_getter: Callable, environ: _Environ) -> bool:

        """
        This function checks Origin of POST methods.
        """

        logger_debug("Check origin...")
        origin = environ_getter("HTTP_ORIGIN")
        url = Server.get_baseurl(environ_getter, environ)

        if origin != url:
            logger_info(f'Bad Origin detected: "{origin}" != "{url}"')
            return False

        logger_info("Correct Origin detected.")
        return True

    @staticmethod
    @log_trace
    def get_json_content(body: bytes, content_type: str) -> JsonValue:

        """
        This functions returns the loaded JSON content.
        """

        logger_debug("Get JSON content...")
        if content_type.startswith("application/json"):
            try:
                return loads(body)
            except (JSONDecodeError, UnicodeDecodeError):
                logger_warning("Non-JSON content detected.")
                logger_info(
                    "This request is not available for"
                    " the default functions of WebScripts."
                )

        return None

    @log_trace
    def parse_body(self, environ: _Environ) -> Tuple[Content, str, bool]:

        """
        This function returns arguments from body.
        """

        environ_get = environ.get

        if not self.check_origin(environ_get, environ):
            logger_warning("Bad Origin detected (CSRF protection).")
            return [], None, False

        logger_debug("Read wsgi.input ...")
        content_length = self.get_content_length(environ)
        body = environ["wsgi.input"].read(content_length)
        content_type = environ["CONTENT_TYPE"]
        logger_debug("wsgi.input is read.")

        if content_length:
            json_content = self.get_json_content(body, content_type)

            if not json_content:
                return body, None, False
            else:
                body = json_content

            return_values = self.try_get_command(body)
            if return_values is not None:
                return return_values

            logger_warning(
                'Section "arguments" is not defined in the JSON content.'
            )
            logger_info(
                "This request is not available for"
                " the default functions of WebScripts"
            )
            return body, None, False

        return [], None, True

    @log_trace
    def app(self, environ: _Environ, respond: FunctionType) -> List[bytes]:

        """
        This function get function page,
        return content page, catch errors and
        return HTTP errors.
        """

        path_info = environ["PATH_INFO"]
        method = environ["REQUEST_METHOD"]
        logger_debug(
            f"Request ({method}) from " f"{get_ip(environ)} on {path_info}."
        )
        path_info_startswith = path_info.startswith
        configuration = self.configuration
        environ["LOG_PATH"] = log_path
        environ["WEBSCRIPTS_PATH"] = server_path
        is_head_method = method == "HEAD"

        logger_debug("Trying to get function page...")
        get_response, filename, is_not_package = self.get_function_page(
            path_info
        )

        logger_debug("Check authentication...")
        user, not_blacklisted = self.check_auth(environ)

        if not not_blacklisted:
            logger_critical(
                f'Blacklist: Error 403 on "{path_info}" for '
                f'"{user.name}" (ID: {user.id}).'
            )
            return self.page_403(None, respond)

        logger_info("User is not blacklisted.")
        logger_debug("Trying to get and parse body...")

        if method == "POST":
            arguments, csrf_token, is_webscripts_request = self.parse_body(
                environ
            )
        elif method == "GET" or is_head_method:
            arguments, csrf_token, is_webscripts_request = [], None, True
        else:
            return self.page_400(method, respond)

        arguments, inputs = self.return_inputs(
            arguments, is_webscripts_request
        )

        if is_not_package and not is_webscripts_request:
            logger_error(f'HTTP 406: for "{user.name}" on "{path_info}"')
            error = "406"
        else:
            logger_info("Request is not rejected as HTTP error 406.")
            error: str = None

        if (
            (
                (not configuration.accept_unknow_user and user.id == 1)
                or (
                    not configuration.accept_unauthenticated_user
                    and user.id == 0
                )
            )
            and configuration.active_auth
        ) and (
            path_info not in configuration.exclude_auth_pages
            and not any(
                path_info_startswith(x)
                for x in configuration.exclude_auth_paths
            )
        ):
            logger_warning(f"Unauthenticated try to get access to {path_info}")
            self.send_headers(respond, "302 Found", {"Location": "/web/auth/"})
            return [
                b"Authentication required:\n\t",
                b" - For API you can use Basic Auth",
                b"\n\t - For API you can use Api-Key",
                b"\n\t - For Web Interface (with Web Browser) use /web/auth/",
            ]

        if get_response is None:
            logger_info("Page 404, cause: no function page.")
            return self.page_404(path_info, respond)

        if error == "406":
            logger_debug("Send response (code 406).")
            return self.page_406(None, respond)

        logger_debug("Trying to execute function page...")
        try:
            error, headers, page = get_response(
                environ,
                user,
                configuration,
                filename,
                arguments,
                inputs,
                csrf_token=csrf_token,
            )
        except Exception as error:
            print_exc()
            error_text = format_exc()
            error = f"{error}\n{error_text}"
            Logs.error(error)
            return self.page_500(error_text, respond)

        if error == "404":
            logger_debug("Send response 404, cause: function page return 404.")
            return self.page_404(path_info, respond)
        elif error == "403":
            logger_debug("Send response 403, cause: function page return 403.")
            return self.page_403(None, respond)
        elif error == "500":
            logger_debug("Send response 500, cause: function page return 500.")
            return self.page_500(page, respond)
        else:
            logger_debug(f"Get custom response for code {error}")
            response = self.send_custom_error("", error)
            if response is not None:
                logger_info(f"Get a response for code {error}")
                error, headers, page = response

        error, headers = self.set_default_values_for_response(error, headers)

        logger_debug("Send headers...")
        self.send_headers(respond, error, headers)
        if is_head_method:
            logger_debug("Is HEAD method, return an empty response body...")
            return []

        return self.return_page(page)

    @log_trace
    def set_default_values_for_response(
        self, error: str, headers: Dict[str, str]
    ) -> Tuple[str, Dict[str, str]]:

        """
        This function returns default error if not defined and
        default headers updated with custom headers.
        """

        if not error:
            logger_debug("Set error code as default error code (200).")
            error = self.error

        logger_debug("Add default and custom headers to the response...")
        default_headers = self.headers.copy()
        default_headers.update(headers)

        return error, default_headers

    @staticmethod
    @log_trace
    def return_page(page: Union[bytes, str, list]) -> List[bytes]:

        """
        This function returns response as a list of bytes.
        """

        if isinstance(page, bytes):
            logger_debug("Send bytes response...")
            return [page]
        elif isinstance(page, str):
            logger_debug("Send str response (encode using utf-8)...")
            return [page.encode()]
        elif isinstance(page, list):
            logger_debug("Send list response...")
            return page

    @log_trace
    def return_inputs(
        self,
        arguments: List[Dict[str, JsonValue]],
        is_webscripts_request: bool,
    ) -> Tuple[List[str], List[str]]:

        """
        This function returns inputs (using Server.get_inputs).
        """

        if is_webscripts_request:
            logger_debug("Trying to get inputs...")
            inputs, arguments = self.get_inputs(arguments)
        else:
            logger_info(
                "Is not a WebScripts request, inputs are "
                "defined as empty list."
            )
            inputs = []

        return arguments, inputs

    @log_trace
    def send_headers(
        self,
        respond: FunctionType,
        error: str = None,
        headers: Dict[str, str] = None,
    ) -> None:

        """
        This function send error code, message and headers.
        """

        if error is None:
            logger_debug("Defined error as default error.")
            error = self.error
        if headers is None:
            logger_debug("Defined headers as default headers.")
            _headers = self.headers
        else:
            logger_debug("Update headers with custom headers...")
            _headers = self.headers.copy()
            _headers.update(headers)

        logger_debug("Call respond WSGI function...")
        respond(error, [(k, v) for k, v in _headers.items()])

    @log_trace
    def page_500(self, error: str, respond: FunctionType) -> List[bytes]:

        """
        This function return error 500 web page.
        """

        error_code = "500 Internal Error"
        logger_debug("Send 500 Internal Error...")
        return self.send_error_page(error_code, error.encode(), respond)

    @log_trace
    def page_404(self, url: str, respond: FunctionType):

        """
        This function return error 404 web page.
        """

        error_code = "404 Not Found"

        logger_debug("Get URLs for 404 debug page...")
        urls = "\n\t - ".join(self.get_URLs())
        error = (
            f"This URL: {url}, doesn't exist"
            f" on this server.\nURLs:\n\t - {urls}"
        )
        logger_error(f"HTTP 404 on {url}")
        return self.send_error_page(error_code, error.encode(), respond)

    @log_trace
    def page_400(self, method: str, respond: FunctionType):

        """This function return error 403 web page."""

        error_code = "400 Bad Request"
        error = (
            "Bad method, method should be GET, "
            f"POST or HEAD not {method}".encode()
        )
        logger_debug("Send 400 Bad Request...")
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def page_401(self, error_description: str, respond: FunctionType):

        """This function return error 401 web page."""

        error_code = "401 Unauthorized"
        error = b"Unauthorized (You don't have permissions)"
        logger_debug("Send 401 Unauthorized...")
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def page_403(self, error_description: str, respond: FunctionType):

        """This function return error 403 web page."""

        error_code = "403 Forbidden"
        error = b"Forbidden (You don't have permissions)"
        logger_debug("Send 403 Forbidden...")
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def page_406(self, error_description: str, respond: FunctionType):

        """This function return error 406 web page."""

        error_code = "406 Not Acceptable"
        error = (
            b"Not Acceptable, your request is not a valid WebScripts request."
        )
        logger_debug("Send 406 Not Acceptable...")
        return self.send_error_page(error_code, error, respond)

    @log_trace
    def send_error_page(
        self, error: str, data: bytes, respond: FunctionType
    ) -> List[bytes]:

        """This function send HTTP errors."""

        code = error[:3]
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        error_ = ""

        logger_debug("Trying to get custom error response...")
        try:
            custom_error, custom_headers, custom_data = self.send_custom_error(
                error, code
            )
        except Exception as exception:
            print_exc()
            error_ = (
                f"{exception.__class__.__name__}: {exception}\n{format_exc()}"
            )
            logger_error(error_)
            custom_data = None

        if self.debug:
            logger_warning("Send debug error page...")
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
            logger_debug("Send custom error page...")
            self.send_headers(respond, custom_error, custom_headers)
            return custom_data

        logger_debug("Send default error page...")
        self.send_headers(respond, error, headers)
        return [
            b"---------------\n",
            f"** ERROR {code} **\n".encode(),
            b"---------------\n",
        ]

    def send_custom_error(
        self, error: str, code: str
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function call custom errors pages.
        """

        logger_debug("Search custom error in packages...")
        packages = self.pages.packages
        # for package in self.pages.packages.__dict__.values():
        for package in dir(packages):
            package = getattr(packages, package)

            if isinstance(package, ModuleType):
                logger_debug(f"Check in {package}...")
                page = package.__dict__.get("page_" + code)

                if page is not None:
                    logger_info(
                        f"Found the custom error page: {package}.page_{code}"
                    )
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

    """
    This generator return configurations dict.
    """

    logger_debug("Get paths for server configuration...")
    paths = [
        join(current_directory, "config", "server.ini"),
        join(current_directory, "config", "server.json"),
    ]
    insert = paths.insert

    if system() == "Windows":
        logger_debug("Add default server configuration for Windows...")
        insert(0, join(server_path, "config", "nt", "server.json"))
        insert(0, join(server_path, "config", "nt", "server.ini"))
    else:
        logger_debug("Add default server configuration for Unix...")
        insert(0, join(server_path, "config", "server.json"))
        insert(0, join(server_path, "config", "server.ini"))

    for filename in paths:
        logger_debug(f"Check {filename}...")

        if exists(filename):
            logger_warning(f"Configuration file detected: {filename}")
            if filename.endswith(".json"):
                yield loads(get_file_content(filename))
            elif filename.endswith(".ini"):
                yield get_ini_dict(filename)
        else:
            logger_info(f"Configuration named {filename} doesn't exists.")

    for filename in arguments.config_cfg:
        logger_debug("Check configuration file (cfg) added in arguments...")

        if exists(filename):
            logger_warning(
                f"Configuration file detected (type cfg): {filename}"
            )
            yield get_ini_dict(filename)
        else:
            logger_error(
                f"Configuration file {filename} doesn't exists "
                "(defined in arguments)."
            )

    for filename in arguments.config_json:
        logger_debug("Check configuration file (json) added in arguments...")

        if exists(filename):
            logger_warning(
                f"Configuration file detected (type json): {filename}"
            )
            yield loads(get_file_content(filename))
        else:
            logger_error(
                f"Configuration file {filename} doesn't exists "
                "(defined in arguments)."
            )

    args = arguments.__dict__
    del args["config_cfg"]
    del args["config_json"]

    yield {k: v for k, v in args.items() if v is not None}


@log_trace
def logs_configuration(configuration: NameSpace) -> None:

    """
    This function configure ROOT logger from
    configuration files and command line arguments.
    """

    log_config = {}

    if (
        isinstance(configuration.log_level, str)
        and configuration.log_level.isdigit()
    ):
        configuration.log_level = int(configuration.log_level)
    elif isinstance(configuration.log_level, str):
        configuration.log_level = getattr(logging, configuration.log_level, 0)
    elif not isinstance(configuration.log_level, int):
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

    """
    This function add configuration in ServerConfiguration.
    """

    current_configuration = Configuration()
    add_conf = current_configuration.add_conf
    have_server_conf = "server" in config.keys()

    if have_server_conf:
        logger_debug('"server" section detected in configuration.')
        server = config.pop("server")

    logger_debug("Adding other configuration in Configuration object...")
    add_conf(**config)

    if have_server_conf:
        logger_debug("Add server section in Configuration object...")
        add_conf(**server)

    logger_debug("Build type of configurations...")
    current_configuration.build_types()

    config_dict = current_configuration.get_dict()
    logger_debug(
        "Add configurations in ServerConfiguration: " f"{config_dict}"
    )
    configuration.add_conf(**config_dict)
    return configuration


def configure_logs_system() -> None:

    """This function try to create the logs directory
    if not found and configure logs."""

    if not isdir("logs"):
        logger_info("./logs directory not found.")
        try:
            mkdir("logs")
        except PermissionError:
            logger_error(
                "Get a PermissionError to create "
                "the non-existent ./logs directory."
            )
        else:
            logger_info("./logs directory is created.")

    fileConfig(
        join(server_path, "config", "loggers.ini"),
        disable_existing_loggers=False,
    )

    basicConfig(
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

    logger_debug("Get module error_pages...")
    error_pages = getattr(Pages.packages, "error_pages", None)
    if error_pages:
        logger_debug("Start a Thread to send email...")
        Thread(
            target=error_pages.Request.send_mail,
            args=(
                configuration,
                message,
            ),
        ).start()
        return 0

    logger_error("Module error_pages is not detected, can not send email.")
    return 1


def main() -> int:

    """
    Main function to build the
    configurations and launch the server.
    """

    if "--test-running" in argv:
        NO_START = True
        argv.remove("--test-running")
    else:
        NO_START = False

    configure_logs_system()
    args = parse_args()

    logger_debug("Load configurations...")

    configuration = Configuration()
    for config in get_server_config(args):
        configuration = add_configuration(configuration, config)

    configuration = add_configuration(configuration, args.__dict__)

    logs_configuration(configuration)

    logger_debug("Check and type configurations...")
    configuration.set_defaults()
    configuration.check_required()
    configuration.get_unexpecteds()
    configuration.build_types()

    logger_info("Configurations are loaded.")

    if getattr(configuration, "debug", None):
        logger_debug("Debug mode detected: export configuration...")
        configuration.export_as_json()

    logger_debug("Build server with configurations...")
    server = Server(configuration)

    httpd = simple_server.make_server(
        server.interface, server.port, server.app
    )
    logger_info("Server is built.")

    logger_debug("Trying to send email notification...")
    send_mail(
        configuration,
        f"Server is up on http://{server.interface}:{server.port}/.",
    )

    logger_info("Check hardening of the WebScripts server...")
    hardening(server, Logs, send_mail)

    logger_warning(
        f"Starting server on http://{server.interface}:{server.port}/ ..."
    )
    print(copyright)

    if NO_START:
        logger_warning(
            "Detected as test only. Do not start"
            " the server. Exit with code 0."
        )
        return 0

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger_critical("Server is down.")
        httpd.server_close()

    logger_debug("Trying to send email notification...")
    send_mail(
        configuration,
        f"Server is down on http://{server.interface}:{server.port}/.",
    )
    logger_debug("Exit with code 0.")
    return 0


if __name__ == "__main__":
    exit(main())
