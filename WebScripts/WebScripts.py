#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool runs CLI scripts and displays output in a Web Interface.
#    Copyright (C) 2021, 2022, 2023  Maurice Lambert

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
This tool runs CLI scripts and displays output in a Web Interface.

This file is the "main" file of this package (implements the main function,
the Server class and the Configuration class).
"""

__version__ = "1.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file is the "main" file of this package (implements the main function,
the Server class and the Configuration class).
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Configuration", "Server", "main"]

from os.path import basename, abspath, join, dirname, normpath, exists, isdir
from types import SimpleNamespace, ModuleType, FunctionType, MethodType
from typing import TypeVar, Tuple, List, Dict, Union, Set, Iterable
from sys import exit, modules as sys_modules, argv
from os import _Environ, mkdir, environ
from collections.abc import Iterator, Callable
from argparse import Namespace, ArgumentParser
from traceback import print_exc, format_exc
from json.decoder import JSONDecodeError
from logging.config import fileConfig
from collections import defaultdict
from wsgiref import simple_server
from urllib.parse import quote
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
        ScriptConfig,
        CallableFile,
        TokenCSRF,
        Blacklist,
        Session,
        JsonValue,
        DefaultNamespace,
        get_ini_dict,
        lib_directory as server_path,
        current_directory,
        log_trace,
        get_ip,
        Logs,
        get_environ,
        get_file_content,
        get_arguments_count,
        get_real_path,
        WebScriptsSecurityError,
        WebScriptsArgumentError,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
        logger_debug,
        logger_info,
        logger_access,
        logger_response,
        logger_command,
        logger_warning,
        logger_error,
        logger_critical,
        check_file_permission,
    )
else:
    from hardening import main as hardening
    from Pages import (
        Pages,
        Argument,
        User,
        ScriptConfig,
        CallableFile,
        TokenCSRF,
        Blacklist,
        Session,
        JsonValue,
        DefaultNamespace,
        get_ini_dict,
        lib_directory as server_path,
        current_directory,
        log_trace,
        get_ip,
        Logs,
        get_environ,
        get_file_content,
        get_arguments_count,
        get_real_path,
        WebScriptsSecurityError,
        WebScriptsArgumentError,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
        logger_debug,
        logger_info,
        logger_access,
        logger_response,
        logger_command,
        logger_warning,
        logger_error,
        logger_critical,
        check_file_permission,
    )

NameSpace = TypeVar("NameSpace", SimpleNamespace, Namespace)
FunctionOrNone = TypeVar("FunctionOrNone", FunctionType, None)
Content = TypeVar(
    "Content", List[Dict[str, JsonValue]], Dict[str, JsonValue], bytes
)


class Configuration(DefaultNamespace):

    """
    This class build the configuration from dict(s) with
    configuration files and arguments.
    """

    __defaults__ = {
        "interface": "127.0.0.1",
        "port": 8000,
        "urls": {},
        "modules": [],
        "js_path": [],
        "cgi_path": [],
        "log_level": 0,
        "statics_path": [],
        "scripts_path": [],
        "modules_path": [],
        "exclude_auth_paths": ["/static/", "/js/"],
        "exclude_auth_pages": ["/api/", "/auth/", "/web/auth/"],
        "auth_script": None,
        "active_auth": False,
        "webproxy_number": None,
        "documentations_path": [],
        "accept_unknow_user": True,
        "force_file_permissions": True,
        "auth_failures_to_blacklist": None,
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
        "ini_scripts_config",
        "log_level",
        "log_filename",
        "log_level",
        "log_format",
        "log_date_format",
        "log_encoding",
        "auth_failures_to_blacklist",
        "blacklist_time",
        "webproxy_number",
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
        "admin_groups": List[int],
        "modules": list,
        "modules_path": list,
        "js_path": list,
        "statics_path": list,
        "documentations_path": list,
        "exclude_auth_paths": list,
        "exclude_auth_pages": list,
        "scripts_path": list,
        "json_scripts_config": list,
        "ini_scripts_config": list,
        "auth_failures_to_blacklist": int,
        "blacklist_time": int,
        "smtp_starttls": bool,
        "smtp_port": int,
        "smtp_ssl": bool,
        "admin_adresses": list,
        "csrf_max_time": int,
        "session_max_time": int,
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
                            "Add configuration list using INI/CFG syntax."
                        )
                        value = value.split(",")

                    if isinstance(value, list):
                        logger_debug(
                            "Add configuration list using JSON syntax."
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

    """
    This class implements the WebScripts server.
    """

    class CommonsClasses:
        Argument = Argument
        User = User
        ScriptConfig = ScriptConfig
        CallableFile = CallableFile
        TokenCSRF = TokenCSRF
        Blacklist = Blacklist
        Session = Session
        DefaultNamespace = DefaultNamespace
        Pages = Pages

    @log_trace
    def __init__(self, configuration: Configuration):
        self.configuration = configuration
        self.interface: str = configuration.interface
        self.port: int = configuration.port

        logger_debug("Create default value for WebScripts server...")
        self.unknow: Dict = {"id": 1, "name": "Unknow", "groups": [0, 1]}
        self.not_authenticated: Dict = {
            "id": 0,
            "name": "Not Authenticated",
            "groups": [0],
        }
        self.error: str = "200 OK"
        self.pages_cache = defaultdict(lambda: (None, None))
        self.pages = Pages()
        self.logs = Logs
        self.routing_url = configuration.urls

        self.send_mail = send_mail

        if configuration.webproxy_number is not None:
            configuration.webproxy_number += 1

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

        self.path = server_path
        self.research_filename = get_real_path
        self.research_file_content = get_file_content
        self.get_environ_strings = get_environ
        self.environ = environ

        self.set_default_headers(headers, security, configuration)
        self.add_module_or_package()
        self.add_paths()

        packages = Pages.packages
        packages = [getattr(packages, attr) for attr in dir(packages)]
        environ["WEBSCRIPTS_MODULES"] = ":".join(
            [
                package.__file__
                for package in packages
                if isinstance(package, ModuleType) and package.__file__
            ]
        )

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
                "default-src 'self'; navigate-to 'self'; worker-src "
                "'none'; style-src-elem 'self'; style-src-attr 'none';"
                " style-src 'self'; script-src-attr 'none'; object-src"
                " 'none'; media-src 'none'; manifest-src 'none'; "
                "frame-ancestors 'none'; connect-src 'self'; font-src"
                " 'none'; img-src 'self'; base-uri 'none'; child-src"
                " 'none'; form-action 'none'; script-src 'self' "
                "'require-trusted-types-for'"
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
            if "Configurations" not in configuration.modules:
                configuration.modules.append("Configurations")
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
        ip = environ_get("REMOTE_IP")

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
                self,
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
                self,
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

        """
        This function add packages and modules to build custom page.
        """

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
            path_ = package._webscripts_filepath = normpath(package.__file__)

            if check_file_permission(configuration, path_, recursive=True):
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
                    glob = join(dirname_, normpath(glob))
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
    def get_function_page(
        self, path: str, filename: str
    ) -> Tuple[FunctionOrNone, str, bool]:

        """
        This function find function from URL path.
        If the function is a WebScripts built-in function,
        return the function, filename and True. Else return the
        function, filename and False.
        """

        path = tuple(path.split("/")[1:-1])
        cache = self.pages_cache

        logger_debug("Trying to get function page from cache...")
        function, is_not_package = cache[path]

        if function:
            return function, filename, is_not_package

        get_attributes = self.get_attributes
        pages = self.pages

        logger_debug(
            "Trying to found function page from default WebScripts function..."
        )
        function, is_not_package = get_attributes(pages, path)

        if function is None:
            logger_debug("Trying to found function page from packages...")
            function, is_not_package = get_attributes(
                pages.packages, path, False
            )

        cache[path] = (function, is_not_package)
        return function, filename, is_not_package

    @log_trace
    def get_URLs(self) -> List[str]:

        """
        This function return a list of urls (scripts, documentation...)
        and the start of the URL of custom packages.
        """

        urls = ["/api/", "/web/", *self.routing_url.keys()]
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
    ) -> Tuple[FunctionOrNone, bool]:

        """
        This function get recursive attribute from object.
        """

        def check_argument_count():
            if isinstance(object_, FunctionType) or type(object_) == type:
                if arg_count == 7:
                    logger_info(f"Function page found {object_}.")
                    return object_, is_not_package
                else:
                    return ValueError
            elif isinstance(object_, MethodType):
                if arg_count == 8:
                    logger_info(f"Method page found {object_}.")
                    return object_, is_not_package
                else:
                    return ValueError

        for attribute in attributes:
            logger_debug(f"Trying to get {attribute} from {object_}")
            object_ = getattr(object_, attribute, None)

            if object_ is None:
                return None, is_not_package

        logger_debug("Get arguments length and check it...")
        arg_count = get_arguments_count(object_)

        function = check_argument_count()
        if function is None:
            if isinstance(object_, Callable):
                object_ = object_.__call__
                function = check_argument_count()

        if function is not None and function is not ValueError:
            return function

        logger_warning(
            "The function cannot be called with 7 "
            "arguments or the method cannot be called "
            "with 8 arguments."
        )
        return None, is_not_package

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
                # To protect secrets, do not log arguments !
                append(argument)

        logger_debug("Remove inputs from arguments...")
        for i, input_ in enumerate(inputs):
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
    def get_fullurl(environ: _Environ) -> str:

        """
        This function returns the full URL (based on the PEP 3333).

        Link: https://peps.python.org/pep-3333/
        """

        scheme = environ["wsgi.url_scheme"]
        url = scheme + "://"

        host = environ.get("HTTP_HOST")
        query = environ.get("QUERY_STRING")

        if host:
            url += host
        else:
            url += environ["SERVER_NAME"]

            if scheme == "https":
                if environ["SERVER_PORT"] != "443":
                    url += ":" + environ["SERVER_PORT"]
            else:
                if environ["SERVER_PORT"] != "80":
                    url += ":" + environ["SERVER_PORT"]

        url += quote(environ.get("SCRIPT_NAME", ""))
        url += quote(environ.get("PATH_INFO", ""))

        if query:
            url += "?" + query

        return url

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
    def app(self, environ_: _Environ, respond: MethodType) -> List[bytes]:

        """
        This function get function page,
        return content page, catch errors and
        return HTTP errors.
        """

        # environ: _Environ = self.environ
        # encodevalue: Callable = environ.encodevalue
        # encodekey: Callable = environ.encodekey
        environ = {key: value for key, value in self.environ.items()}
        # environ = _Environ(
        #     environ._data.copy(),
        #     encodekey,
        #     environ.decodekey,
        #     encodevalue,
        #     environ.decodevalue
        # )

        # d_setitem: Callable = environ._data.__setitem__
        # [d_setitem(encodekey(key), encodevalue(value)) if isinstance(value, str) else d_setitem(encodekey(key), value) for key, value in environ_.items()]

        environ.update(environ_)

        path_info = environ["PATH_INFO"]
        method = environ["REQUEST_METHOD"]
        configuration = self.configuration
        port = environ.setdefault("REMOTE_PORT", "0")
        ip = environ["REMOTE_IP"] = get_ip(
            environ, configuration.webproxy_number
        )
        logger_access(f"Request ({method}) from {ip!r}:{port} on {path_info}.")

        if ip is None:
            logger_critical("IP Spoofing: Error 403.")
            return self.page_403(environ, self.unknow, "", None, respond)

        path_info_startswith = path_info.startswith
        path, filename = path_info.rsplit("/", 1)
        path += "/"
        is_head_method = method == "HEAD"

        new_url = self.routing_url.get(path)
        if new_url is not None:
            logger_info(f"Routing URL: {path_info!r} to {new_url!r}.")
            path = new_url

        logger_debug("Trying to get function page...")
        get_response, filename, is_not_package = self.get_function_page(
            path, filename
        )

        logger_debug("Check authentication...")
        user, not_blacklisted = self.check_auth(environ)

        if not not_blacklisted:
            logger_critical(
                f'Blacklist: Error 403 on "{path_info}" for '
                f'"{user.name}" (ID: {user.id}).'
            )
            return self.page_403(environ, user, filename, None, respond)

        logger_info("User is not blacklisted.")
        logger_debug("Trying to get and parse body...")

        if method == "POST":
            arguments, csrf_token, is_webscripts_request = self.parse_body(
                environ
            )
        elif method == "GET" or is_head_method:
            arguments, csrf_token, is_webscripts_request = [], None, True
        else:
            return self.page_400(environ, user, filename, method, respond)

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
            self.send_headers(
                environ, respond, "302 Found", {"Location": "/web/auth/"}
            )
            return [
                b"Authentication required:\n\t",
                b" - For API you can use Basic Auth",
                b"\n\t - For API you can use Api-Key",
                b"\n\t - For Web Interface (with Web Browser) use /web/auth/",
            ]

        if get_response is None:
            logger_info("Page 404, cause: no function page.")
            return self.page_404(environ, user, filename, path_info, respond)

        if error == "406":
            logger_debug("Send response (code 406).")
            return self.page_406(environ, user, filename, None, respond)

        logger_debug("Trying to execute function page...")
        try:
            error, headers, page = get_response(
                environ,
                user,
                self,
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
            return self.page_500(environ, user, filename, error_text, respond)

        if error == "404" and not page:
            logger_debug("Send response 404, cause: function page return 404.")
            return self.page_404(environ, user, filename, path_info, respond)
        elif error == "403" and not page:
            logger_debug("Send response 403, cause: function page return 403.")
            return self.page_403(environ, user, filename, None, respond)
        elif error == "500" and not page:
            logger_debug("Send response 500, cause: function page return 500.")
            return self.page_500(environ, user, filename, page, respond)
        elif not page:
            logger_debug(f"Get custom response for code {error}")
            response = self.send_custom_error(
                environ, user, filename, "", error
            )
            if response is not None:
                logger_info(f"Get a response for code {error}")
                error, headers, page = response

        error, headers = self.set_default_values_for_response(error, headers)

        logger_debug("Send headers...")
        self.send_headers(environ, respond, error, headers)
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
    def return_page(page: Union[bytes, str, Iterable[bytes]]) -> List[bytes]:

        """
        This function returns response as a list of bytes.
        """

        if isinstance(page, bytes):
            logger_debug("Send bytes response...")
            return [page]
        elif isinstance(page, str):
            logger_debug("Send str response (encode using utf-8)...")
            return [page.encode()]
        elif isinstance(page, Iterable):
            logger_debug("Send iterable response...")
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
        environ: _Environ,
        respond: MethodType,
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

        logger_response(
            f"Response {environ['REMOTE_IP']!r}:{environ['REMOTE_PORT']} "
            f"{environ['REQUEST_METHOD']} {environ['PATH_INFO']} {error!r}"
        )
        respond(error, [(k, v) for k, v in _headers.items()])

    @log_trace
    def page_500(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        error: Union[str, bytes, Iterable[bytes]],
        respond: MethodType,
    ) -> List[bytes]:

        """
        This function return error 500 web page.
        """

        error_code = "500 Internal Error"
        logger_debug("Send 500 Internal Error...")
        return self.send_error_page(
            environ,
            user,
            filename,
            error_code,
            b"".join(self.return_page(error)),
            respond,
        )

    @log_trace
    def page_404(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        url: str,
        respond: MethodType,
    ):

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
        return self.send_error_page(
            environ, user, filename, error_code, error.encode(), respond
        )

    @log_trace
    def page_400(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        method: str,
        respond: MethodType,
    ):

        """
        This function return error 400 web page.
        """

        error_code = "400 Bad Request"
        error = (
            "Bad method, method should be GET, "
            f"POST or HEAD not {method}".encode()
        )
        logger_debug("Send 400 Bad Request...")
        return self.send_error_page(
            environ, user, filename, error_code, error, respond
        )

    @log_trace
    def page_401(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        error_description: str,
        respond: MethodType,
    ):

        """
        This function return error 401 web page.
        """

        error_code = "401 Unauthorized"
        error = b"Unauthorized (You don't have permissions)"
        logger_debug("Send 401 Unauthorized...")
        return self.send_error_page(
            environ, user, filename, error_code, error, respond
        )

    @log_trace
    def page_403(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        error_description: str,
        respond: MethodType,
    ):

        """
        This function return error 403 web page.
        """

        error_code = "403 Forbidden"
        error = b"Forbidden (You don't have permissions)"
        logger_debug("Send 403 Forbidden...")
        return self.send_error_page(
            environ, user, filename, error_code, error, respond
        )

    @log_trace
    def page_406(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        error_description: str,
        respond: MethodType,
    ):

        """
        This function return error 406 web page.
        """

        error_code = "406 Not Acceptable"
        error = (
            b"Not Acceptable, your request is not a valid WebScripts request."
        )
        logger_debug("Send 406 Not Acceptable...")
        return self.send_error_page(
            environ, user, filename, error_code, error, respond
        )

    @log_trace
    def send_error_page(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        error: str,
        data: bytes,
        respond: MethodType,
    ) -> List[bytes]:

        """
        This function send HTTP errors.
        """

        code = error[:3]
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        error_ = ""

        logger_debug("Trying to get custom error response...")
        try:
            custom_error, custom_headers, custom_data = self.send_custom_error(
                environ, user, filename, error, code
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
            self.send_headers(environ, respond, error, headers)
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
            self.send_headers(environ, respond, custom_error, custom_headers)
            return custom_data

        logger_debug("Send default error page...")
        self.send_headers(environ, respond, error, headers)
        return [
            b"---------------\n",
            f"** ERROR {code} **\n".encode(),
            b"---------------\n",
        ]

    def send_custom_error(
        self,
        environ: _Environ,
        user: User,
        filename: str,
        error: str,
        code: str,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function call custom errors pages.
        """

        logger_debug("Search custom error in packages...")

        cache = self.pages_cache
        function_name = "page_" + code
        function, _ = cache[function_name]

        if function is not None:
            logger_debug("Get custom error page (function) from cache.")
            return function(environ, user, self, filename, error)

        packages = self.pages.packages
        for package in dir(packages):
            package = getattr(packages, package)

            if isinstance(package, ModuleType):
                logger_debug(f"Check in {package}...")
                page = getattr(package, function_name, None)

                if page is not None:
                    logger_info(
                        f"Found the custom error page: {package}.page_{code}"
                    )
                    cache[function_name] = page, False
                    return page(
                        environ,
                        user,
                        self,
                        filename,
                        error,
                    )


@log_trace
def parse_args(argv: List[str] = argv) -> Namespace:

    """
    This function parse command line arguments.
    """

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
    return parser.parse_args(argv[1:])


@log_trace
def get_server_config(arguments: Namespace, secure: bool = False) -> Iterator[dict]:

    """
    This generator return configurations dict.
    """

    logger_debug("Get paths for server configuration...")
    paths = [
        join(current_directory, "config", "server.ini"),
        join(current_directory, "config", "server.json"),
    ]
    insert = paths.insert

    temp_config = Configuration()
    temp_config.force_file_permissions = secure

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

        if exists(filename) and check_file_permission(temp_config, filename):
            logger_warning(f"Configuration file detected: {filename}")
            if filename.endswith(".json"):
                yield loads(get_file_content(filename))
            elif filename.endswith(".ini"):
                yield get_ini_dict(filename)
        else:
            logger_info(f"Configuration named {filename} doesn't exists.")

    for filename in arguments.config_cfg:
        logger_debug("Check configuration file (cfg) added in arguments...")

        if exists(filename) and check_file_permission(temp_config, filename):
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

        if exists(filename) and check_file_permission(temp_config, filename):
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
    log_level = getattr(configuration, "log_level", 0)

    if isinstance(log_level, str) and log_level.isdigit():
        configuration.log_level = int(log_level)
    elif isinstance(log_level, str):
        configuration.log_level = getattr(logging, log_level, 0)
    elif not isinstance(log_level, int):
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

    logs_configuration(current_configuration)
    current_configuration.build_types()

    config_dict = current_configuration.get_dict()
    logger_debug(
        "Add configurations in ServerConfiguration: " f"{config_dict}"
    )
    configuration.add_conf(**config_dict)
    return configuration


def configure_logs_system(secure: bool = False) -> Tuple[Set[str], Set[str]]:

    """
    This function try to create the logs directory
    if not found and configure logs.
    """

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

    log_file = get_real_path(join("config", "loggers.ini"))

    temp_config = Configuration()
    temp_config.force_file_permissions = secure

    if not check_file_permission(temp_config, log_file):
        raise WebScriptsSecurityError(
            "Logs configuration file/directory permissions are"
            " insecure. Remote code execution can be exploited."
        )

    fileConfig(
        log_file,
        disable_existing_loggers=False,
    )

    Logs.log_response.handlers[0].baseFilename

    logs_path = set()
    log_files = set()

    logs_path_add = logs_path.add
    log_files_add = log_files.add

    for logger_ in (
        "log_trace",
        "log_response",
        "log_access",
        "log_command",
        "log_debug",
        "log_info",
        "log_warning",
        "log_error",
        "log_critical",
        "file",
    ):
        logger = getattr(Logs, logger_)
        handlers = logger.handlers

        for handler in handlers:
            filepath = getattr(handler, "baseFilename", None)
            if filepath is not None:
                logs_path_add(dirname(filepath))
                log_files_add(
                    (logger_.split("_", 1)[1] if "_" in logger_ else "all")
                    + "?"
                    + filepath
                )

    environ["WEBSCRIPTS_LOGS_PATH"] = "|".join(logs_path)
    environ["WEBSCRIPTS_LOGS_FILES"] = "|".join(log_files)
    return logs_path, log_files


def send_mail(*args, **kwargs) -> int:

    """
    This function send a mail to adminitrators
    using the error_pages modules.

    Return 0 if message is sent else 1.
    """

    logger_debug("Get module error_pages...")
    error_pages = getattr(Pages.packages, "error_pages", None)
    if error_pages:
        logger_debug("Start a Thread to send email...")
        Thread(
            target=error_pages.Request.send_mail,
            args=args,
            kwargs=kwargs,
        ).start()
        return 0

    logger_error("Module error_pages is not detected, can not send email.")
    return 1


def default_configuration(argv: List[str] = argv, secure: bool = False) -> Configuration:

    """
    This function builds the default configuration.
    """

    log_paths, log_files = configure_logs_system(secure)
    environ["WEBSCRIPTS_PATH"] = server_path
    args = parse_args(argv)

    logger_debug("Load configurations...")

    configuration = Configuration()
    configuration.logs_path = list(log_paths)
    configuration.log_files = list(log_files)
    for config in get_server_config(args, secure):
        configuration = add_configuration(configuration, config)

    configuration = add_configuration(configuration, args.__dict__)

    logger_debug("Check and type configurations...")
    configuration.set_defaults()
    configuration.check_required()
    configuration.get_unexpecteds()
    configuration.build_types()

    urls_section = configuration.get("urls_section")

    if urls_section is not None:
        urls = getattr(configuration, urls_section, None)

        if urls is None:
            raise WebScriptsConfigurationError(
                f"The 'urls_section' ({urls_section!r}) " "does not exists."
            )

        if not isinstance(urls, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in urls.items()
        ):
            raise WebScriptsConfigurationError(
                f"Key {urls_section!r} (the url section) should be a section"
                ' of strings (dict or JSON object {"string": "string"}).'
            )

        configuration.urls = urls
    else:
        configuration.urls = {}

    configuration.__types__["log_level"] = int
    configuration.data_dir = datapath = get_real_path(
        getattr(configuration, "data_dir", "data"), is_dir=True
    )

    environ["WEBSCRIPTS_DATA_PATH"] = datapath
    environ["WEBSCRIPTS_DOCUMENTATION_PATH"] = ":".join(
        configuration.documentations_path
    )

    logger_info("Configurations are loaded.")

    return configuration

def prepare_server(secure: bool = True) -> Server:

    """
    This function prepares server to be launched securly.
    """

    configuration = default_configuration(argv, secure)
    debug = getattr(configuration, "debug", None)

    if debug:
        logger_debug("Debug mode detected: export configuration...")
        configuration.export_as_json()

    logger_debug("Build server with configurations...")
    server = Server(configuration)

    return server

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

    secure: bool = "--security" not in argv

    server = prepare_server(secure)
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
    if secure:
        hardening(server)

    if debug:
        # second export to get all configurations
        logger_debug("Debug mode detected: export configuration...")
        configuration.export_as_json()

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
