#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool run scripts and display the result in a Web Interface.
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
This tool run scripts and display the result in a Web Interface.

This file implements commons functions and class for WebScripts package.
"""

__version__ = "0.1.3"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file implements commons functions and class for WebScripts package.
"""
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

__all__ = [
    "User",
    "Session",
    "Argument",
    "JsonValue",
    "TokenCSRF",
    "Blacklist",
    "ScriptConfig",
    "CallableFile",
    "ServerConfiguration",
]


from os.path import join, normcase, isfile, dirname, splitext, basename, split
from typing import TypeVar, Tuple, List, Dict
from secrets import token_bytes, token_hex
from configparser import ConfigParser
from collections.abc import Callable
from subprocess import Popen, PIPE  # nosec
from types import SimpleNamespace
from base64 import b64encode
from re import fullmatch
from glob import iglob
from time import time
from json import load

if __package__:
    from .utils import (
        DefaultNamespace,
        get_ini_dict,
        server_path as lib_directory,
        working_directory as current_directory,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_arguments_count,
        # doRollover,
        # rotator,
        # namer,
        # Handler,
        get_real_path,
        get_encodings,
        WebScriptsConfigurationError,
        WebScriptsArgumentError,
        WebScriptsConfigurationTypeError,
        WebScriptsSecurityError,
        logger_debug,
        logger_info,
        logger_access,
        logger_response,
        logger_command,
        logger_warning,
        logger_error,
        logger_critical,
        IS_WINDOWS,
        check_file_permission,
    )
else:
    from utils import (
        DefaultNamespace,
        get_ini_dict,
        server_path as lib_directory,
        working_directory as current_directory,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_arguments_count,
        # doRollover,
        # rotator,
        # namer,
        # Handler,
        get_real_path,
        get_encodings,
        WebScriptsConfigurationError,
        WebScriptsArgumentError,
        WebScriptsConfigurationTypeError,
        WebScriptsSecurityError,
        logger_debug,
        logger_info,
        logger_access,
        logger_response,
        logger_command,
        logger_warning,
        logger_error,
        logger_critical,
        IS_WINDOWS,
        check_file_permission,
    )

JsonValue = TypeVar("JsonValue", str, int, bool, None, List[str], List[int])
ServerConfiguration = TypeVar("ServerConfiguration")
ScriptConfig = TypeVar("ScriptConfig")
Blacklist = TypeVar("Blacklist")
Pages = TypeVar("Pages")

Configuration = TypeVar("Configuration", ServerConfiguration, SimpleNamespace)


class Argument(DefaultNamespace):

    """
    This class build argument for script.
    """

    __required__ = ["name"]
    __optional__ = [
        "list",
        "input",
        "example",
        "html_type",
        "is_advanced",
        "description",
        "default_value",
        "predefined_values",
        "javascript_attributs",
    ]
    __defaults__ = {
        "javascript_attributs": {},
        "default_value": None,
        "is_advanced": False,
        "html_type": "text",
        "description": None,
        "example": None,
        "input": None,
    }
    __types__ = {
        "predefined_values": list,
        "is_advanced": bool,
        "input": bool,
        "list": bool,
    }

    @staticmethod
    @log_trace
    def get_command(
        name: str, argument: Dict[str, JsonValue]
    ) -> List[Dict[str, JsonValue]]:

        """
        This function return list for command line execution.
        """

        if name.startswith("-"):
            list_ = [{"value": name, "input": False}]
            argument["input"] = False
        else:
            list_ = []

        value = argument["value"]

        if value is None:
            return []
        elif isinstance(value, str):
            if value == "":
                return []

            list_.append(argument)

        elif isinstance(value, bool):
            if value is False:
                return []
            else:
                return [{"value": name, "input": False}]

        elif isinstance(value, (int, float)):
            list_.append({"value": str(value), "input": argument["input"]})

        elif isinstance(value, list):
            while "" in value:
                value.remove("")

            while None in value:
                value.remove(None)

            if len(value) == 0:
                return []

            for arg in value:

                if isinstance(arg, int):
                    arg = str(arg)

                list_.append({"value": arg, "input": argument["input"]})
        else:
            raise WebScriptsArgumentError(
                "Argument type must be: list, str, float, int, bool or None."
                f" Not {type(value)} ({value})"
            )

        return list_


class ScriptConfig(DefaultNamespace):

    """
    This class makes script configurations.
    """

    __required__ = ["name", "dirname"]
    __defaults__ = {
        "documentation_content_type": "text/html",
        "command_generate_documentation": None,
        "stderr_content_type": "text/plain",
        "content_type": "text/plain",
        "documentation_file": None,
        "print_real_time": False,
        "minimum_access": None,
        "access_groups": None,
        "access_users": None,
        "no_password": False,
        "description": None,
        "launcher": None,
        "timeout": None,
        "category": "",
        "path": "",
        "args": [],
    }
    __optional__ = [
        "command_generate_documentation",
        "documentation_content_type",
        "stderr_content_type",
        "documentation_file",
        "minimum_access",
        "access_groups",
        "content_type",
        "access_users",
        "no_password",
        "description",
        "category",
        "launcher",
        "timeout",
        "path",
        "args",
    ]
    __types__ = {
        "access_groups": List[int],
        "access_users": List[int],
        "minimum_access": int,
        "no_password": bool,
        "timeout": int,
    }

    @log_trace
    def build_args(self, configuration: Configuration):

        """
        This function build Arguments from self.args: List[Dict[str, str]]
        """

        args = []
        for arg in self.args:
            arg = Argument.default_build(**arg)

            javascript_section = arg.get("javascript_section")
            if javascript_section is not None:
                javascript_configuration = configuration.get(
                    javascript_section
                )

                if not isinstance(javascript_configuration, dict):
                    raise WebScriptsConfigurationError(
                        f'"{javascript_section}" doesn\'t exist or '
                        "is not a javascript object (a dictionnary)"
                    )

                arg.javascript_attributs = javascript_configuration

            args.append(arg)

        self.args = args

    @classmethod
    @log_trace
    def build_scripts_from_configuration(
        cls, server_configuration: ServerConfiguration
    ) -> Dict[str, ScriptConfig]:

        """
        This function build scripts from server
        configuration and configurations files.
        """

        scripts_config = cls.get_scripts_from_configuration(
            server_configuration, server_configuration
        )

        json_scripts_config = getattr(
            server_configuration, "json_scripts_config", []
        )
        ini_scripts_config = getattr(
            server_configuration, "ini_scripts_config", []
        )
        server_configuration.configuration_files = (
            configuration_files
        ) = getattr(server_configuration, "configuration_files", {})

        for dirname_ in (lib_directory, current_directory):

            for config_path in ini_scripts_config:
                config_path = join(dirname_, normcase(config_path))

                for config_filename in iglob(config_path):
                    if not check_file_permission(
                        server_configuration, config_filename
                    ):
                        continue

                    configuration = DefaultNamespace()
                    temp_configurations = get_ini_dict(config_filename)
                    configuration.update(**temp_configurations)

                    scripts_config.update(
                        cls.get_scripts_from_configuration(
                            configuration, server_configuration
                        )
                    )
                    configuration_files[
                        get_real_path(config_filename)
                    ] = temp_configurations

            for config_path in json_scripts_config:
                config_path = join(dirname_, normcase(config_path))

                for config_filename in iglob(config_path):
                    if not check_file_permission(
                        server_configuration, config_filename
                    ):
                        continue

                    configuration = DefaultNamespace()

                    with open(config_filename) as file:
                        temp_configurations = load(file)
                        configuration.update(**temp_configurations)

                    scripts_config.update(
                        cls.get_scripts_from_configuration(
                            configuration, server_configuration
                        )
                    )
                    configuration_files[config_filename] = temp_configurations

        return scripts_config

    @classmethod
    @log_trace
    def get_scripts_from_configuration(
        cls,
        configuration: Configuration,
        server_configuration: ServerConfiguration,
    ) -> Dict[str, ScriptConfig]:

        """
        This function build scripts from ServerConfiguration.
        """

        scripts = getattr(configuration, "scripts", {})
        scripts_config = {}

        for name, section_config in scripts.items():
            script_section = getattr(configuration, section_config, None)
            logger_warning(
                f"Script found: {name!r} (section: {section_config!r})"
            )

            if script_section is None:
                raise WebScriptsConfigurationError(
                    f"section {section_config!r} doesn't exist (to configure "
                    f"script named {name!r})"
                )
            else:
                script_section = script_section.copy()

            (
                script_configuration,
                script_section,
            ) = cls.get_script_config_from_specific_file_config(
                script_section, configuration, server_configuration
            )

            script_section["args"] = cls.get_arguments_from_config(
                script_section.pop("args", None), script_configuration
            )
            script_section[
                "documentation_file"
            ] = cls.get_documentation_from_configuration(
                script_section,
                name,
                getattr(server_configuration, "documentations_path", []),
            )
            script_section["name"] = name

            path_ = script_section.get("path")
            script_section["path"] = script_path = get_real_path(path_)
            if script_path is None:
                script_path = script_section["path"] = cls.get_script_path(
                    server_configuration, script_section
                )
            elif not isfile(script_path):
                raise WebScriptsConfigurationError(
                    f"Location for script named {name!r} "
                    f"({script_path!r}) doesn't exist."
                )

            if script_section.get("launcher") is None:
                script_section[
                    "launcher"
                ] = cls.get_Windows_default_script_launcher(script_section)

            script_section["dirname"] = dirname(script_path)

            if not check_file_permission(
                server_configuration, script_path, executable=True
            ):
                continue

            build = scripts_config[name] = cls.default_build(**script_section)
            build.build_args(script_configuration)

            if path_ is None:
                build.path_is_defined = False
            else:
                build.path_is_defined = True

        return scripts_config

    @staticmethod
    @log_trace
    def get_Windows_default_script_launcher(
        script_config: Dict[str, JsonValue]
    ) -> str:

        """
        This function gets the Windows default launcher to execute a file.
        """

        if not IS_WINDOWS:
            return None

        logger_info(
            f"Research default launcher for script {script_config['name']}"
        )
        extension = splitext(script_config["path"])[1]

        if (
            fullmatch(r"[.]\w+", extension) is None
        ):  # raise an error against command injection
            logger_critical(
                f'Security Error: this extension "{extension}" is a security '
                "risk (for security reason this extension is blocked)."
            )
            raise WebScriptsSecurityError(
                f"Invalid extension: {extension} (for security "
                "reason this extension is blocked)"
            )

        command = [
            r"C:\WINDOWS\system32\cmd.exe",
            "/c",
            "assoc",
            extension,
        ]
        logger_command("Get launcher from extension: " + repr(command))

        process = Popen(
            command,  # protection against command injection
            stdout=PIPE,
            stderr=PIPE,
            text=True,
        )  # nosec
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            return None
        filetype = stdout.split("=")[1] if "=" in stdout else ""

        command = [r"C:\WINDOWS\system32\cmd.exe", "/c", "ftype", filetype]
        logger_command("Get launcher from extension: " + repr(command))

        process = Popen(
            command,
            stdout=PIPE,
            stderr=PIPE,
            text=True,
        )  # nosec
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            return None
        launcher = (
            stdout.split()[0].split("=")[1].replace('"', "")
            if "=" in stdout
            else None
        )

        if launcher is not None:
            logger_warning(
                f"Launcher found for {script_config['name']}: {launcher}"
            )

        return launcher

    @staticmethod
    @log_trace
    def get_script_path(
        server_configuration: ServerConfiguration,
        script_config: Dict[str, JsonValue],
    ) -> str:

        """
        This function return a script path from configuration.
        """

        for dirname_ in (lib_directory, current_directory):
            for directory in server_configuration.scripts_path:
                script_path = join(
                    dirname_, normcase(directory), script_config["name"]
                )
                if isfile(script_path):
                    logger_info(
                        f"Found script named: {script_config['name']} in "
                        f"location: {script_path}"
                    )
                    return script_path

        raise WebScriptsConfigurationError(
            f"No location found for script named {script_config['name']}"
        )

    @staticmethod
    @log_trace
    def get_documentation_from_configuration(
        script_config: Dict[str, JsonValue], name: str, paths: List[str]
    ) -> str:

        """
        This function get documentation from script configuration
        or search it in documentation path.
        """

        doc_file = script_config.get("documentation_file")

        if doc_file is None:
            for path_ in paths:
                doc_files = join(path_, f"{splitext(basename(name))[0]}.*")
                for doc_file in iglob(doc_files):
                    logger_debug(f"Documentation file found for {name}")
                    break
        else:
            logger_debug(f"Documentation file found for {name}")

        return doc_file

    @staticmethod
    @log_trace
    def get_arguments_from_config(
        arguments_section: str, configuration: Dict[str, Dict[str, JsonValue]]
    ) -> List[Dict[str, JsonValue]]:

        """
        This function get arguments list of script.
        """

        if arguments_section is not None:
            args_config = configuration.get(arguments_section)

            if args_config is None:
                raise WebScriptsConfigurationError(
                    f"{arguments_section} "
                    "section doesn't exist in configuration"
                )

            arguments_config = []
            for name, arg_section in args_config.items():
                arg_config = configuration.get(arg_section)

                if arg_config is None:
                    raise WebScriptsConfigurationError(
                        f"{arg_section} section doesn't exist "
                        f'in configuration (for argument named "{name}")'
                    )

                arg_config["name"] = name
                arguments_config.append(arg_config)

                logger_info(f"Argument named {name} found and configured.")
        else:
            arguments_config = []

        return arguments_config

    @staticmethod
    @log_trace
    def get_script_config_from_specific_file_config(
        script_config: Dict[str, JsonValue],
        configuration: Dict[str, JsonValue],
        server_configuration: Dict[str, JsonValue],
    ) -> Tuple[dict, dict]:

        """
        This function return all configuration and
        script configuration from configuration.
        """

        configuration_file = script_config.get("configuration_file")

        if configuration_file is not None:
            if configuration_file.endswith(".json"):
                file = get_file_content(configuration_file, as_iterator=True)
                configuration = load(file)
                file.close()
            else:
                config = ConfigParser(
                    allow_no_value=True, inline_comment_prefixes="#"
                )
                config.read(configuration_file)
                configuration = config._sections

            script_config = configuration.get("script")

            if script_config is None:
                raise WebScriptsConfigurationError(
                    f'Section "script" is not defined in {configuration_file}'
                )

            server_configuration.configuration_files = (
                configuration_files
            ) = getattr(server_configuration, "configuration_files", {})
            configuration_files[
                get_real_path(configuration_file)
            ] = configuration

        return configuration, script_config

    @log_trace
    def get_JSON_API(self) -> Dict:

        """
        This function return a dict for JSON API
        (visible configuration for user).
        """

        json_api = self.get_dict()

        for key in (
            "command_generate_documentation",
            "documentation_file",
            "print_real_time",
            "minimum_access",
            "access_groups",
            "access_users",
            "no_password",
            "launcher",
            "timeout",
            "dirname",
            "path",
        ):
            del json_api[key]

        if "secrets" in json_api.keys():
            del json_api["secrets"]

        arguments = json_api.pop("args")
        json_api["args"] = []

        for argument in arguments:
            json_api["args"].append(argument.get_dict())

        return json_api

    @staticmethod
    @log_trace
    def get_docfile_from_configuration(
        configuration: ServerConfiguration, filename: str
    ) -> str:

        """
        This method returns the script documentation
        path if it exists.
        """

        for dirname_ in (lib_directory, current_directory):
            for doc_glob in configuration.documentations_path:

                doc_glob = join(dirname_, normcase(doc_glob))
                for doc in iglob(doc_glob):

                    doc_dirname, doc_filename = split(doc)
                    no_extension, extension = splitext(doc_filename)

                    if no_extension == splitext(basename(filename))[0]:
                        return doc


class User(DefaultNamespace):

    """
    This class implements User object.
    """

    __required__ = [
        "id",
        "name",
        "groups",
        "csrf",
        "ip",
        "categories",
        "scripts",
        "check_csrf",
    ]
    __types__ = {
        "id": int,
        "check_csrf": bool,
        "groups": List[int],
        "scripts": list,
        "categories": list,
    }
    __defaults__ = {
        "csrf": {},
        "groups": [],
        "scripts": ["*"],
        "categories": ["*"],
        "check_csrf": False,
    }


class CallableFile(Callable):

    """
    This class build callable object to return
    Web files content or script output.
    """

    template_script_path: str = get_real_path("static/templates/script.html")
    template_header_path: str = get_real_path("static/templates/header.html")
    template_footer_path: str = get_real_path("static/templates/footer.html")
    template_index_path: str = get_real_path("static/templates/index.html")

    template_script: str = get_file_content(template_script_path)
    template_header: str = get_file_content(template_header_path)
    template_footer: str = get_file_content(template_footer_path)
    template_index: str = get_file_content(template_index_path)

    @log_trace
    def __init__(
        self, type_: str, path_: str, filename: str, config: dict = None
    ):
        self.path = path_
        self.type = type_
        self.config = config
        self.filename = filename
        self.extension = splitext(path_)[1].lower()

    @log_trace
    def __call__(self, user: User) -> Tuple[str, Dict[str, str], List[bytes]]:
        if self.type == "js":
            return (
                "200 OK",
                {"Content-Type": "text/javascript; charset=utf-8"},
                get_file_content(self.path, as_iterator=True),
            )
        elif self.type == "static":
            if self.is_html():
                return (
                    "200 OK",
                    {"Content-Type": "text/html; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".css":
                return (
                    "200 OK",
                    {"Content-Type": "text/css; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".ico":
                return (
                    "200 OK",
                    {"Content-Type": "image/x-icon"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".png":
                return (
                    "200 OK",
                    {"Content-Type": "image/png"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.is_jpeg():
                return (
                    "200 OK",
                    {"Content-Type": "image/jpeg"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".gif":
                return (
                    "200 OK",
                    {"Content-Type": "image/gif"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".json":
                return (
                    "200 OK",
                    {"Content-Type": "application/json; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".txt":
                return (
                    "200 OK",
                    {"Content-Type": "text/plain; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".pdf":
                return (
                    "200 OK",
                    {"Content-Type": "application/pdf; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".csv":
                return (
                    "200 OK",
                    {"Content-Type": "text/csv; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.is_tiff():
                return (
                    "200 OK",
                    {"Content-Type": "image/tiff"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.is_xml():
                return (
                    "200 OK",
                    {"Content-Type": "application/xml; charset=utf-8"},
                    get_file_content(self.path, as_iterator=True),
                )
            elif self.extension == ".svg":
                return (
                    "200 OK",
                    {"Content-Type": "image/svg+xml"},
                    get_file_content(self.path, as_iterator=True),
                )
            else:
                return (
                    "200 OK",
                    {"Content-Type": "application/octet-stream"},
                    get_file_content(self.path, as_iterator=True),
                )
        elif self.type == "script":
            nonce = token_hex(20)
            return (
                "200 OK",
                {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": (
                        "default-src 'self'; navigate-to 'self'; worker-src "
                        "'none'; style-src-elem 'self'; style-src-attr 'none';"
                        " style-src 'self'; script-src-attr 'none'; object-src"
                        " 'none'; media-src 'none'; manifest-src 'none'; "
                        "frame-ancestors 'none'; connect-src 'self'; font-src"
                        " 'none'; img-src 'self'; base-uri 'none'; child-src"
                        " 'none'; form-action 'none'; script-src 'self' "
                        f"'nonce-{nonce}' 'require-trusted-types-for'"
                    ),
                },
                CallableFile.template_script
                % {
                    "name": self.filename,
                    "user": user.name,
                    "csrf": TokenCSRF.build_token(user),
                    "nonce": nonce,
                    "header": self.template_header,
                    "footer": self.template_footer,
                },
            )
            # return (
            #     "200 OK",
            #     {"Content-Type": "text/html"},
            #     CallableFile.template_script
            #     % {
            #         "name": self.filename,
            #         "user": user.name,
            #         "csrf": TokenCSRF.build_token(user),
            #         "nonce": nonce,
            #     },
            # )

    def is_xml(self) -> bool:

        """
        This function compare extension with xml extensions.
        """

        return self.extension in (
            ".xml",
            ".xsd",
            ".xslt",
            ".tld",
            ".dtml",
            ".rss",
            ".opml",
        )

    def is_html(self) -> bool:

        """
        This function compare extension with html extensions.
        """

        return self.extension in (".html", ".htm", ".shtml", ".xhtml")

    def is_jpeg(self) -> bool:

        """
        This function compare extension with jpeg extensions.
        """

        return self.extension in (".jpg", ".jpeg", ".jpe")

    def is_tiff(self) -> bool:

        """
        This function compare extension with tif extensions.
        """

        return self.extension in (".tiff", ".tif")


class Blacklist:

    """
    This class implement blacklist.
    """

    def __init__(
        self,
        configuration: ServerConfiguration,
        last_blacklist: Blacklist = None,
    ):
        logger_debug("New blacklist object...")
        self.time = time()

        blacklist_time = getattr(configuration, "blacklist_time", None)

        if blacklist_time is None:
            self.counter = 1
            logger_debug("Counter initialized, cause: no blacklist time.")
        else:
            if last_blacklist is None:
                self.counter = 1
                logger_debug("Counter initialized, cause: no blacklist.")
            else:
                if (
                    last_blacklist.time + configuration.blacklist_time
                    >= self.time
                ):
                    counter = self.counter = last_blacklist.counter + 1
                    logger_info(f"Counter increment: {counter}.")
                else:
                    self.counter = 1
                    logger_debug(
                        "Counter initialized, cause: blacklist time exceeded."
                    )

    @log_trace
    def is_blacklist(self, configuration: ServerConfiguration) -> bool:

        """
        This function return True if this object is blacklisted.
        """

        blacklist_time = getattr(configuration, "blacklist_time", None)
        auth_failures_to_blacklist = getattr(
            configuration, "auth_failures_to_blacklist", None
        )

        if auth_failures_to_blacklist is None:
            logger_debug(
                "Not blacklisted, cause: configuration "
                '"auth_failures_to_blacklist" is None.'
            )
            return False

        if self.counter > auth_failures_to_blacklist:
            if blacklist_time is None:
                logger_debug("Not blacklisted, cause: blacklist time is None")
                return False

            is_blacklisted = blacklist_time + self.time >= time()
            logger_info(f"Blacklist state: {is_blacklisted}")
            return is_blacklisted
        else:
            logger_debug(
                "Not blacklisted, cause: counter less than "
                'configuration "auth_failures_to_blacklist".'
            )
            return False

    def __str__(self) -> str:

        """
        This function returns a string to represent the Blacklist object.
        """

        return (
            f"Blacklist(counter={self.counter}, "
            f"blacklist_time={time() - self.time})"
        )


class TokenCSRF:

    """
    This class brings together the functions related to the CSRF token
    """

    @staticmethod
    @log_trace
    def build_token(user: User) -> str:

        """
        This function build a CSRF token for a user.
        """

        token = b64encode(token_bytes(48)).decode()
        user.csrf[token] = time()
        return token

    @staticmethod
    @log_trace
    def check_csrf(
        user: User,
        token: str,
        csrf_max_time: float = 300,
        referer: str = None,
        baseurl: str = None,
    ) -> bool:

        """
        This function check the validity of a csrf token.
        """

        max_time = time() - csrf_max_time

        if referer and baseurl and not referer.startswith(baseurl):
            logger_error(
                f"Referrer error: referer ({referer!r}) "
                f"do not start with baseurl ({baseurl!r})."
            )
            TokenCSRF.clean(user, max_time)
            return False

        timestamp = user.csrf.pop(token, 0)

        if timestamp >= max_time:
            return True
        else:
            logger_warning(
                f"CSRF Token has expired ({timestamp} >= {max_time})"
            )
            TokenCSRF.clean(user, max_time)
            return False

    @staticmethod
    @log_trace
    def clean(user: User, max_time: float) -> None:

        """
        This function clean all old CSRF tokens for a user.
        """

        to_delete = []

        for token, timestamp in user.csrf.items():

            if timestamp <= max_time:
                to_delete.append(token)

        for key in to_delete:
            del user.csrf[key]


class Session:

    """
    Object to implement session.
    """

    def __init__(self, user: User, ip: str):
        self.cookie = token_hex(64)
        self.time = time()
        self.user = user
        self.ip = ip

    def __str__(self) -> str:

        """
        This function returns a string to represent the Session object.
        """

        return (
            f"Session(Time={time() - self.time}, IP={self.ip}, "
            f"Cookie={self.cookie}, User={self.user})"
        )

    @classmethod
    @log_trace
    def build_session(cls, user: User, ip: str, Pages: Pages) -> str:

        """
        This function build and add session and return the cookie.
        """

        session: Session = cls(user, ip)
        Pages.sessions[user.id] = session
        return f"{user.id}:{session.cookie}"

    @staticmethod
    @log_trace
    def check_session(
        cookie: str,
        pages: Pages,
        ip: str,
        default_user: User,
        session_max_time: float = 3600,
    ) -> User:

        """
        This function check session validity and return user.
        """

        if cookie.startswith("SessionID="):
            cookie = cookie[10:]
        else:
            logger_error("Session cookie do not start with 'SessionID='.")
            return default_user

        if ":" in cookie:
            user_id, cookie_session = cookie.split(":", 1)
        else:
            logger_error("Invalid session cookie: ':' not in cookie")
            return default_user

        if user_id.isdigit():
            session = pages.sessions.get(int(user_id), None)
        else:
            logger_error("Cookie: UserID is not digit.")
            return default_user

        if session is None:
            logger_info("Session not found.")
            return default_user

        if (
            session.ip == ip
            and session.time + session_max_time >= time()
            and session.cookie == cookie_session
        ):
            return session.user
        else:
            logger_warning("Session: Bad IP or session expired or bad cookie.")
            return default_user
