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

This file implement some tools for WebScripts server
and scripts (Logs, Namespace for configuration, ...)."""

from typing import TypeVar, List, Dict, _SpecialGenericAlias, _GenericAlias
from types import SimpleNamespace, FunctionType, MethodType
from os import path, _Environ, device_encoding
from subprocess import check_call, DEVNULL  # nosec
from configparser import ConfigParser
from contextlib import suppress
from functools import wraps
from logging import Logger
import logging.config
import platform
import logging
import locale
import json

if __package__:
    from .Errors import (
        WebScriptsConfigurationError,
        WebScriptsArgumentError,
        MissingAttributesError,
        WebScriptsConfigurationTypeError,
        WebScriptsSecurityError,
    )
else:
    from Errors import (
        WebScriptsConfigurationError,
        WebScriptsArgumentError,
        MissingAttributesError,
        WebScriptsConfigurationTypeError,
        WebScriptsSecurityError,
    )

__version__ = "0.0.7"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This tools run scripts and display the result in a Web Interface.

This file implement some tools for WebScripts server
and scripts (Logs, Namespace for configuration, ...)."""
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

__all__ = [
    "Logs",
    "DefaultNamespace",
    "log_trace",
    "get_ip",
    "get_file_content",
    "get_real_path",
    "get_encodings",
    "get_ini_dict",
    "server_path",
]

StrOrBytes = TypeVar("StrOrBytes", str, bytes)
DefaultNamespace = TypeVar("DefaultNamespace")


class _Logs:

    """This class implement basic python logs."""

    console: Logger = logging.getLogger("WebScripts.console")
    file: Logger = logging.getLogger("WebScripts.file")

    log_debug: Logger = logging.getLogger("WebScripts.debug")
    log_info: Logger = logging.getLogger("WebScripts.info")
    log_warning: Logger = logging.getLogger("WebScripts.warning")
    log_error: Logger = logging.getLogger("WebScripts.error")
    log_critical: Logger = logging.getLogger("WebScripts.critical")

    log_trace: Logger = logging.getLogger("WebScripts.trace")

    def debug(log: str) -> None:

        """This function implement basic python debug logs for WebScripts."""

        indent_log = f"{' ' * 7}{log}"

        Logs.log_debug.debug(indent_log)
        Logs.console.debug(f"\x1b[32m{indent_log}\x1b[0m")
        Logs.file.debug(indent_log)
        logging.debug(indent_log)

    def info(log: str) -> None:

        """This function implement basic python info logs for WebScripts."""

        indent_log = f"{' ' * 8}{log}"

        Logs.log_info.info(indent_log)
        Logs.console.info(f"\x1b[34m{indent_log}\x1b[0m")
        Logs.file.info(indent_log)
        logging.info(indent_log)

    def warning(log: str) -> None:

        """This function implement basic python warning logs for WebScripts."""

        indent_log = f"{' ' * 5}{log}"

        Logs.log_warning.warning(indent_log)
        Logs.console.warning(f"\x1b[33m{indent_log}\x1b[0m")
        Logs.file.warning(indent_log)
        logging.warning(indent_log)

    def error(log: str) -> None:

        """This function implement basic python error logs for WebScripts."""

        indent_log = f"{' ' * 7}{log}"

        Logs.log_error.error(indent_log)
        Logs.console.error(f"\x1b[35m{indent_log}\x1b[0m")
        Logs.file.error(indent_log)
        logging.error(indent_log)

    def critical(log: str) -> None:

        """This function implement basic python critical logs for WebScripts."""

        indent_log = f"{' ' * 4}{log}"

        Logs.log_critical.critical(indent_log)
        Logs.console.critical(f"\x1b[31m{indent_log}\x1b[0m")
        Logs.file.critical(indent_log)
        logging.critical(indent_log)

    def exception(log: str) -> None:

        """This function implement basic python exception (error) logs for WebScripts."""

        indent_log = f"{' ' * 7}{log}"

        Logs.log_error.exception(indent_log)
        Logs.console.exception(indent_log)
        Logs.file.exception(indent_log)
        logging.exception(indent_log)

    def trace(log: str) -> None:

        """This function implement trace logs for WebScripts."""

        indent_log = f"{' ' * 4}{log}"

        Logs.log_trace.log(5, indent_log)
        logging.log(5, indent_log)

    def config(*args, **kwargs):

        """This function config ROOT logger."""

        logging.basicConfig(*args, **kwargs)


class WindowsLogs(_Logs):

    """This class log on Windows."""

    app: str = "WebScripts"

    def debug(log: str) -> None:

        """This function log debugs on Windows."""

        super(WindowsLogs, WindowsLogs).debug(log)
        if WINDOWS_LOGS:
            ReportEvent(
                WindowsLogs.app,
                0x3E8,
                eventCategory=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                strings=[log],
            )

    def info(log: str) -> None:

        """This function log infos on Windows."""

        super(WindowsLogs, WindowsLogs).info(log)
        if WINDOWS_LOGS:
            ReportEvent(
                WindowsLogs.app,
                0x7D0,
                eventCategory=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                strings=[log],
            )

    def warning(log: str) -> None:

        """This function log warnings on Windows."""

        super(WindowsLogs, WindowsLogs).warning(log)
        if WINDOWS_LOGS:
            ReportEvent(
                WindowsLogs.app,
                0xBB8,
                eventCategory=win32evtlog.EVENTLOG_WARNING_TYPE,
                strings=[log],
            )

    def error(log: str) -> None:

        """This function log errors on Windows."""

        super(WindowsLogs, WindowsLogs).error(log)
        if WINDOWS_LOGS:
            ReportEvent(
                WindowsLogs.app,
                0xFA0,
                eventCategory=win32evtlog.EVENTLOG_ERROR_TYPE,
                strings=[log],
            )

    def critical(log: str) -> None:

        """This function log criticals on Windows."""

        super(WindowsLogs, WindowsLogs).critical(log)
        if WINDOWS_LOGS:
            ReportEvent(
                WindowsLogs.app,
                0x1388,
                eventCategory=win32evtlog.EVENTLOG_ERROR_TYPE,
                strings=[log],
            )


class LinuxLogs(_Logs):

    """This class log on Linux."""

    def debug(log: str) -> None:

        """This function log debugs on Linux."""

        super(LinuxLogs, LinuxLogs).debug(log)
        ReportEvent(syslog.LOG_DEBUG, log)

    def info(log: str) -> None:

        """This function log infos on Linux."""

        super(LinuxLogs, LinuxLogs).info(log)
        ReportEvent(syslog.LOG_INFO, log)

    def warning(log: str) -> None:

        """This function log warnings on Linux."""

        super(LinuxLogs, LinuxLogs).warning(log)
        ReportEvent(syslog.LOG_WARNING, log)

    def error(log: str) -> None:

        """This function log errors on Linux."""

        super(LinuxLogs, LinuxLogs).error(log)
        ReportEvent(syslog.LOG_ERR, log)

    def critical(log: str) -> None:

        """This function log criticals on Linux."""

        super(LinuxLogs, LinuxLogs).critical(log)
        ReportEvent(syslog.LOG_CRIT, log)


def log_trace(function: FunctionType):

    """This decorator trace functions (start and end)"""

    @wraps(function)
    def wrapper(*args, **kwds):
        # if isinstance(function, classmethod) or isinstance(function, staticmethod):
        #    name = function.__func__.__name__
        # else:
        #    name = function.__name__

        Logs.trace(f"Start {function.__name__}...")
        values = function(*args, **kwds)
        Logs.trace(f"End of {function.__name__}.")
        return values

    return wrapper


if platform.system() == "Windows":
    try:
        from win32evtlogutil import ReportEvent
        import win32evtlog
    except ImportError:
        WINDOWS_LOGS = False
    else:
        WINDOWS_LOGS = True

    check_call(
        [
            r"C:\WINDOWS\system32\reg.exe",
            "add",
            r"HKEY_CURRENT_USER\Console",
            "/v",
            "VirtualTerminalLevel",
            "/t",
            "REG_DWORD",
            "/d",
            "0x00000001",
            "/f",
        ],
        stdout=DEVNULL,
        stderr=DEVNULL,
    )  # Active colors in console (for logs) # nosec

    Logs = WindowsLogs
    if not WINDOWS_LOGS:
        Logs.error("PyWin32 is not installed, no Windows Event Logs.")
else:
    from syslog import syslog as ReportEvent
    import syslog

    Logs = LinuxLogs


class DefaultNamespace(SimpleNamespace):

    """This class build simple namespace with default
    attributs."""

    def __init__(
        self,
        required: List[str] = [],
        optional: List[str] = [],
        default: dict = {},
        types: dict = {},
    ):
        self.__required__ = required or getattr(self, "__required__", [])
        self.__optional__ = optional or getattr(self, "__optional__", [])
        self.__default__ = default or getattr(self, "__default__", {})
        self.__types__ = types or getattr(self, "__types__", {})

        for attr, value in self.__default__.items():
            if getattr(self, attr, None) is None:
                setattr(self, attr, value)

    @log_trace
    def update(self, **kwargs):

        """This function add/update attributes with **kwargs arguments."""

        self.__dict__.update(kwargs)

    @log_trace
    def check_required(self) -> None:

        """This function checks required attributes
        if one of required attributes is missing this
        function raise MissingAttributesError."""

        for attribut in self.__required__:
            if getattr(self, attribut, None) is None:
                raise MissingAttributesError(
                    f"{attribut} is missing in {self.__class__.__name__}."
                )

    @log_trace
    def get_missings(self) -> List[str]:

        """This function checks required attributes
        and return a List[str] of missing required attributes."""

        missings = []

        for attribut in self.__required__:
            if getattr(self, attribut, None) is None:
                missings.append(attribut)

        return missings

    @log_trace
    def get_unexpecteds(self, log: bool = True) -> List[str]:

        """This function return a List[str] of
        all attributes not in optional and
        required attributes.

        If log argument is True a Warning log message is
        write for all unexpected attributes."""

        all_ = self.__required__ + self.__optional__
        unexpecteds = []

        for attribut in self.get_dict().keys():
            if attribut not in all_:
                unexpecteds.append(attribut)

                if log:
                    Logs.warning(
                        f"{attribut} is an unexpected argument in {self.__class__.__name__}"
                    )

        return unexpecteds

    @log_trace
    def get_dict(self) -> None:

        """This function return a dict of attributes."""

        dict_ = self.__dict__.copy()

        to_delete = []

        for attribut, value in dict_.items():
            if isinstance(value, MethodType) or (
                attribut.startswith("__") and attribut.endswith("__")
            ):
                to_delete.append(attribut)

        for attribut in to_delete:
            del dict_[attribut]

        return dict_

    @log_trace
    def export_as_json(self, name: str = None) -> None:

        """This function export namespace values (useful for debugging)."""

        if name is None:
            name = f"export_{self.__class__.__name__}.json"

        export = self.get_dict()

        with open(name, "w") as file:
            json.dump(export, file, indent=4)

    @log_trace
    def build_types(self) -> None:

        """This function build type from configuration values."""

        for attribut, type_ in self.__types__.items():
            value = getattr(self, attribut, None)

            if value is None:
                continue

            if isinstance(type_, _GenericAlias) or isinstance(
                type_, _SpecialGenericAlias
            ):
                if isinstance(value, type_.__origin__):
                    continue
            else:
                if isinstance(value, type_):
                    continue

            if type_ is bool:
                if value == "true":
                    setattr(self, attribut, True)
                elif value == "false":
                    setattr(self, attribut, False)
                else:
                    raise WebScriptsConfigurationError(
                        f"{attribut} must be boolean (true or false) but is {value}"
                    )

            if type_ is int:
                if value.isdigit():
                    setattr(self, attribut, int(value))
                else:
                    raise WebScriptsConfigurationError(
                        f"{attribut} must be an integer but is {value}"
                    )

            if type_ is List[str] or type_ is list:
                setattr(self, attribut, value.split(","))

            if type_ is List[int]:
                int_list = []
                for digit in value.split(","):
                    if digit.isdigit():
                        int_list.append(int(digit))
                    else:
                        raise WebScriptsConfigurationError(
                            f"{attribut} must be a list of integer but contain {digit}"
                        )
                setattr(self, attribut, int_list)

    @log_trace
    def set_defaults(self) -> None:

        """This function set defaults attribut with defaults values."""

        for attr, value in self.__defaults__.items():
            setattr(self, attr, getattr(self, attr, value))

    @log_trace
    def get(self, key: str, default=None):

        """Compatibility with dict."""

        return getattr(self, key, default)

    @log_trace
    def __getitem__(self, key: str):

        """Compatibility with dict."""

        return getattr(self, key)

    @classmethod
    @log_trace
    def default_build(cls, **kwargs) -> DefaultNamespace:

        """Default build for DefaultNamespace (set defaults, add values, check
        requirements and unexpected values and build types)."""

        namespace = cls()
        namespace.set_defaults()
        namespace.update(**kwargs)
        namespace.check_required()
        namespace.get_unexpecteds()
        namespace.build_types()
        return namespace


@log_trace
def get_encodings():

    """This function returns the probable encodings."""

    encoding = locale.getpreferredencoding()
    if encoding is not None:
        yield encoding

    encoding = device_encoding(0)
    if encoding is not None:
        yield encoding

    yield "utf-8"  # Default for Linux
    yield "cp1252"  # Default for Windows
    yield "latin-1"  # Can read all files


@log_trace
def get_ini_dict(filename: str) -> Dict[str, Dict[str, str]]:

    """This function return a dict from ini filename."""

    config = ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
    config.read(filename)
    return config._sections


@log_trace
def get_ip(environ: _Environ) -> str:

    """This function return the real IP."""

    return (
        environ.get("X_REAL_IP")
        or environ.get("X_FORWARDED_FOR")
        or environ.get("X_FORWARDED_HOST")
        or environ.get("REMOTE_ADDR")
    )


@log_trace
def get_file_content(file_path, *args, **kwargs) -> StrOrBytes:

    """This function return the file content."""

    if "encoding" in kwargs:
        with open(get_real_path(file_path), *args, **kwargs) as file:
            content = file.read()
        return content

    for encoding in get_encodings():
        with suppress(UnicodeDecodeError):
            with open(get_real_path(file_path), *args, **kwargs) as file:
                content = file.read()
            return content

    raise UnicodeDecodeError("No encoding found to open this file.")


@log_trace
def get_real_path(file_path: str) -> str:

    """This function return the real path for files."""

    if file_path is None:
        return file_path

    if platform.system() == "Windows":
        length = 2
        index = 1
        character = ":"
    else:
        length = 1
        index = 0
        character = "/"

    file_path = path.normcase(file_path)
    server_file_path = path.join(server_path, file_path)

    if path.isfile(file_path):
        return file_path
    elif (
        len(file_path) > length
        and file_path[index] != character
        and path.isfile(server_file_path)
    ):
        return server_file_path

    raise FileNotFoundError(f"[WebScripts] No such file or directory: '{file_path}'")


server_path = path.dirname(__file__)

date_format = "%Y-%m-%d %H:%M:%S"
logging.addLevelName(5, "TRACE")
