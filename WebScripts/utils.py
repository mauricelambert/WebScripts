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

This file implements some tools for WebScripts server
and scripts (Logs, Namespace for configuration, ...).
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web
Interface.

This file implements some tools for WebScripts server
and scripts (Logs, Namespace for configuration, ...).
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

__all__ = [
    "Logs",
    "DefaultNamespace",
    "log_trace",
    "get_ip",
    "get_arguments_count",
    "get_file_content",
    "get_real_path",
    "get_encodings",
    "get_ini_dict",
    "server_path",
    "CustomLogHandler",
    # "doRollover",
    # "rotator",
    # "namer",
    "logger_debug",
    "logger_info",
    "logger_access",
    "logger_response",
    "logger_command",
    "logger_warning",
    "logger_error",
    "logger_critical",
    "check_file_permission",
]

from typing import (
    TypeVar,
    List,
    Dict,
    _SpecialGenericAlias,
    _GenericAlias,
    Any,
    Union,
)
from logging import (
    log as log_,
    debug,
    info,
    warning,
    error,
    critical,
    exception,
    addLevelName,
    basicConfig,
    Logger,
    getLogger,
)
from types import (
    SimpleNamespace,
    FunctionType,
    MethodType,
    CodeType,
    FrameType,
)
from os import path, _Environ, device_encoding, remove, stat, getcwd, listdir
from os.path import abspath, isdir, isfile, exists, dirname, normcase, join
from subprocess import check_call, DEVNULL  # nosec
from locale import getpreferredencoding
from configparser import ConfigParser
from collections.abc import Callable
from platform import system
from getpass import getuser
from functools import wraps
from sys import _getframe
from stat import filemode
from gzip import compress
from json import dump
import logging.handlers

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

StrOrBytes = TypeVar("StrOrBytes", str, bytes)
DefaultNamespace = TypeVar("DefaultNamespace")

utils_filename: str = join("WebScripts", "utils.py")
logging_filename: str = join("Lib", "logging")
test_frame: Callable = (
    lambda f, l: (f.endswith(utils_filename) and l < 703)
    or logging_filename in f
)


def get_log_frame() -> FrameType:
    """
    This function returns the frame
    to get file and line of the log call.
    """

    filename: str = utils_filename
    counter: int = 4
    line: int = 0

    while test_frame(filename, line):
        frame: FrameType = _getframe(counter)
        filename: str = frame.f_code.co_filename
        line: int = frame.f_lineno
        counter += 1

    return _getframe(counter)


logging.currentframe = lambda: _getframe(5)

IS_WINDOWS = system() == "Windows"
IP_HEADERS = [
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_REAL_IP",
    "HTTP_X_FORWARDED_HOST",
    "HTTP_CLIENT_IP",
    "REMOTE_ADDR",
]


class _Logs:

    """
    This class implements basic python logs.
    """

    console: Logger = getLogger("WebScripts.console")
    file: Logger = getLogger("WebScripts.file")

    log_debug: Logger = getLogger("WebScripts.debug")
    log_info: Logger = getLogger("WebScripts.info")
    log_warning: Logger = getLogger("WebScripts.warning")
    log_error: Logger = getLogger("WebScripts.error")
    log_critical: Logger = getLogger("WebScripts.critical")

    log_trace: Logger = getLogger("WebScripts.trace")
    log_access: Logger = getLogger("WebScripts.access")
    log_response: Logger = getLogger("WebScripts.response")
    log_command: Logger = getLogger("WebScripts.command")

    def debug(log: str) -> None:
        """
        This function implements basic python debug logs for WebScripts.
        """

        logs_log_debug_debug(log)
        logs_console_debug(f"\x1b[32m{log}\x1b[0m")
        logs_file_debug(log)
        debug(log)

    def info(log: str) -> None:
        """
        This function implements basic python info logs for WebScripts.
        """

        logs_log_info_info(log)
        logs_console_info(f"\x1b[34m{log}\x1b[0m")
        logs_file_info(log)
        info(log)

    def warning(log: str) -> None:
        """
        This function implements basic python warning logs for WebScripts.
        """

        logs_log_warning_warning(log)
        logs_console_warning(f"\x1b[33m{log}\x1b[0m")
        logs_file_warning(log)
        warning(log)

    def error(log: str) -> None:
        """
        This function implements basic python error logs for WebScripts.
        """

        logs_log_error_error(log)
        logs_console_error(f"\x1b[35m{log}\x1b[0m")
        logs_file_error(log)
        error(log)

    def critical(log: str) -> None:
        """
        This function implements basic python critical logs for WebScripts.
        """

        logs_log_critical_critical(log)
        logs_console_critical(f"\x1b[31m{log}\x1b[0m")
        logs_file_critical(log)
        critical(log)

    def exception(log: str) -> None:
        """
        This function implements basic python exception (error) logs for
        WebScripts.
        """

        logs_log_error_exception(log)
        logs_console_exception(log)
        logs_file_exception(log)
        exception(log)

    def trace(log: str) -> None:
        """
        This function implements trace logs for WebScripts.
        """

        logs_log_trace_log(5, log)
        log_(5, log)

    def access(log: str) -> None:
        """
        This function implements access logs for WebScripts.
        """

        logs_log_debug_debug(log)
        logs_log_access_log(25, log)
        logs_console_log(25, f"\x1b[36m{log}\x1b[0m")
        logs_file_log(25, log)
        log_(25, log)

    def response(log: str) -> None:
        """
        This function implements response logs for WebScripts.
        """

        logs_log_debug_debug(log)
        logs_log_response_log(26, log)
        logs_console_log(26, f"\x1b[36m{log}\x1b[0m")
        logs_file_log(26, log)
        log_(26, log)

    def command(log: str) -> None:
        """
        This function implements response logs for WebScripts.
        """

        logs_log_info_info(log)
        logs_log_command_log(27, log)
        logs_console_log(27, f"\x1b[36m{log}\x1b[0m")
        logs_file_log(27, log)
        log_(27, log)

    def config(*args, **kwargs):
        """
        This function config ROOT logger.
        """

        basicConfig(*args, **kwargs)


class WindowsLogs(_Logs):

    """
    This class log on Windows.
    """

    app: str = __package__ or "WebScripts"

    def access(log: str) -> None:
        """
        This function logs access on Windows.
        """

        super(WindowsLogs, WindowsLogs).access(log)
        ReportEvent(
            WindowsLogs.app,
            0x9C4,
            eventCategory=1,
            eventType=EVENTLOG_INFORMATION_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def response(log: str) -> None:
        """
        This function logs response on Windows.
        """

        super(WindowsLogs, WindowsLogs).response(log)
        ReportEvent(
            WindowsLogs.app,
            0xA28,
            eventCategory=1,
            eventType=EVENTLOG_INFORMATION_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def command(log: str) -> None:
        """
        This function logs commands on Windows.
        """

        super(WindowsLogs, WindowsLogs).command(log)
        ReportEvent(
            WindowsLogs.app,
            0xA8C,
            eventCategory=1,
            eventType=EVENTLOG_INFORMATION_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def debug(log: str) -> None:
        """
        This function logs debugs on Windows.
        """

        super(WindowsLogs, WindowsLogs).debug(log)
        ReportEvent(
            WindowsLogs.app,
            0x3E8,
            eventCategory=1,
            eventType=EVENTLOG_INFORMATION_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def info(log: str) -> None:
        """
        This function logs infos on Windows.
        """

        super(WindowsLogs, WindowsLogs).info(log)
        ReportEvent(
            WindowsLogs.app,
            0x7D0,
            eventCategory=1,
            eventType=EVENTLOG_INFORMATION_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def warning(log: str) -> None:
        """
        This function logs warnings on Windows.
        """

        super(WindowsLogs, WindowsLogs).warning(log)
        ReportEvent(
            WindowsLogs.app,
            0xBB8,
            eventCategory=1,
            eventType=EVENTLOG_WARNING_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def error(log: str) -> None:
        """
        This function logs errors on Windows.
        """

        super(WindowsLogs, WindowsLogs).error(log)
        ReportEvent(
            WindowsLogs.app,
            0xFA0,
            eventCategory=1,
            eventType=EVENTLOG_ERROR_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )

    def critical(log: str) -> None:
        """
        This function logs criticals on Windows.
        """

        super(WindowsLogs, WindowsLogs).critical(log)
        ReportEvent(
            WindowsLogs.app,
            0x1388,
            eventCategory=1,
            eventType=EVENTLOG_ERROR_TYPE,
            strings=[log],
            data=log.encode(),
            sid=SID,
        )


class LinuxLogs(_Logs):

    """
    This class logs on Linux.
    """

    def access(log: str) -> None:
        """
        This function logs access on Linux.
        """

        super(LinuxLogs, LinuxLogs).access(log)
        ReportEvent(LOG_INFO, log)

    def response(log: str) -> None:
        """
        This function logs response on Linux.
        """

        super(LinuxLogs, LinuxLogs).response(log)
        ReportEvent(LOG_INFO, log)

    def command(log: str) -> None:
        """
        This function logs command on Linux.
        """

        super(LinuxLogs, LinuxLogs).command(log)
        ReportEvent(LOG_INFO, log)

    def debug(log: str) -> None:
        """
        This function logs debugs on Linux.
        """

        super(LinuxLogs, LinuxLogs).debug(log)
        ReportEvent(LOG_DEBUG, log)

    def info(log: str) -> None:
        """
        This function logs infos on Linux.
        """

        super(LinuxLogs, LinuxLogs).info(log)
        ReportEvent(LOG_INFO, log)

    def warning(log: str) -> None:
        """
        This function logs warnings on Linux.
        """

        super(LinuxLogs, LinuxLogs).warning(log)
        ReportEvent(LOG_WARNING, log)

    def error(log: str) -> None:
        """
        This function logs errors on Linux.
        """

        super(LinuxLogs, LinuxLogs).error(log)
        ReportEvent(LOG_ERR, log)

    def critical(log: str) -> None:
        """
        This function logs criticals on Linux.
        """

        super(LinuxLogs, LinuxLogs).critical(log)
        ReportEvent(LOG_CRIT, log)


def log_trace(
    function: Union[FunctionType, MethodType]
) -> Union[FunctionType, MethodType]:
    """
    This decorator traces functions (start and end).
    """

    @wraps(function)
    def wrapper(*args, **kwds):
        # if (isinstance(function, classmethod)
        # or isinstance(function, staticmethod)):
        #    name = function.__func__.__name__
        # else:
        #    name = function.__name__

        logger_trace(f"Start {function.__name__}...")
        values = function(*args, **kwds)
        logger_trace(f"End of {function.__name__}.")
        return values

    return wrapper


class CustomLogHandler(logging.handlers.RotatingFileHandler):

    """
    This class is a custom logging handler.
    """

    def doRollover(self):
        """
        Do a rollover, as described in __init__().
        """

        if self.stream:
            self.stream.close()
            self.stream = None
        if self.backupCount > 0:
            filename = self.baseFilename
            i = 0
            while exists(filename):
                i += 1
                filename = self.rotation_filename(
                    "%s.%d" % (self.baseFilename, i)
                )

            self.rotate(self.baseFilename, filename)
        if not self.delay:
            self.stream = self._open()

    def namer(self, name: str) -> str:
        """
        This function returns the new name of the old log files.
        """

        return f"{name}.gz"

    def rotator(self, source: str, destination: str) -> None:
        """
        This function compresses old log files.
        """

        with open(source, "rb") as source_file:
            data = source_file.read()
            compressed = compress(data, 9)

            with open(destination, "wb") as destination_file:
                destination_file.write(compressed)

        remove(source)


logging.handlers.CustomLogHandler = CustomLogHandler

if IS_WINDOWS:
    try:
        from win32con import TOKEN_READ
        from win32api import GetCurrentProcess
        from win32evtlogutil import ReportEvent
        from win32security import (
            OpenProcessToken,
            GetTokenInformation,
            TokenUser,
        )
        from win32evtlog import (
            EVENTLOG_INFORMATION_TYPE,
            EVENTLOG_WARNING_TYPE,
            EVENTLOG_ERROR_TYPE,
        )
    except ImportError:
        WINDOWS_LOGS = False
    else:
        WINDOWS_LOGS = True
        SID = GetTokenInformation(
            OpenProcessToken(GetCurrentProcess(), TOKEN_READ), TokenUser
        )[0]

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
else:
    from pwd import getpwuid
    from syslog import (
        syslog as ReportEvent,
        LOG_DEBUG,
        LOG_INFO,
        LOG_WARNING,
        LOG_ERR,
        LOG_CRIT,
    )

    Logs = LinuxLogs


if IS_WINDOWS and WINDOWS_LOGS:
    Logs = WindowsLogs
elif IS_WINDOWS:
    Logs = _Logs

logs_log_debug_debug: Callable = Logs.log_debug.debug
logs_console_debug: Callable = Logs.console.debug
logs_file_debug: Callable = Logs.file.debug
logs_log_info_info: Callable = Logs.log_info.info
logs_console_info: Callable = Logs.console.info
logs_file_info: Callable = Logs.file.info
logs_log_warning_warning: Callable = Logs.log_warning.warning
logs_console_warning: Callable = Logs.console.warning
logs_file_warning: Callable = Logs.file.warning
logs_log_error_error: Callable = Logs.log_error.error
logs_console_error: Callable = Logs.console.error
logs_file_error: Callable = Logs.file.error
logs_log_critical_critical: Callable = Logs.log_critical.critical
logs_console_critical: Callable = Logs.console.critical
logs_file_critical: Callable = Logs.file.critical
logs_log_error_exception: Callable = Logs.log_error.exception
logs_console_exception: Callable = Logs.console.exception
logs_file_exception: Callable = Logs.file.exception
logs_log_trace_log: Callable = Logs.log_trace.log
logs_log_access_log: Callable = Logs.log_access.log
logs_log_response_log: Callable = Logs.log_response.log
logs_log_command_log: Callable = Logs.log_command.log
logs_console_log: Callable = Logs.console.log
logs_file_log: Callable = Logs.file.log


if IS_WINDOWS and not WINDOWS_LOGS:
    Logs.error("PyWin32 is not installed, no Windows Event Logs.")


class DefaultNamespace(SimpleNamespace):

    """
    This class build simple namespace with default
    attributs.
    """

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
        """
        This function add/update attributes with **kwargs arguments.
        """

        self.__dict__.update(kwargs)

    @log_trace
    def check_required(self) -> None:
        """
        This function checks required attributes
        if one of required attributes is missing this
        function raise MissingAttributesError.
        """

        for attribut in self.__required__:
            if getattr(self, attribut, None) is None:
                raise MissingAttributesError(
                    f"{attribut} is missing in {self.__class__.__name__}."
                )

    @log_trace
    def get_missings(self) -> List[str]:
        """
        This function checks required attributes
        and return a List[str] of missing required attributes.
        """

        missings = []

        for attribut in self.__required__:
            if getattr(self, attribut, None) is None:
                missings.append(attribut)

        return missings

    @log_trace
    def get_unexpecteds(self, log: bool = True) -> List[str]:
        """
        This function return a List[str] of
        all attributes not in optional and
        required attributes.

        If log argument is True a Warning log message is
        write for all unexpected attributes.
        """

        all_ = self.__required__ + self.__optional__
        unexpecteds = []

        for attribut in self.get_dict().keys():
            if attribut not in all_:
                unexpecteds.append(attribut)

                if log:
                    logger_warning(
                        f"{attribut} is an unexpected argument "
                        f"in {self.__class__.__name__}"
                    )

        return unexpecteds

    @log_trace
    def get_dict(self) -> None:
        """
        This function return a dict of attributes.
        """

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
        """
        This function export namespace values (useful for debugging).
        """

        if name is None:
            name = f"export_{self.__class__.__name__}.json"

        export = self.get_dict()

        with open(name, "w") as file:
            dump(export, file, indent=4)

    @log_trace
    def build_types(self) -> None:
        """
        This function builds type from configuration values.
        """

        for attribut, type_ in self.__types__.items():
            value = getattr(self, attribut, None)

            if value is None:
                continue

            self.build_type(attribut, value, type_)

    @log_trace
    def build_type(
        self, attribut: str, value: Any, type_: type = None
    ) -> None:
        """
        This function builds type from configuration value.
        """

        def get_number(
            functype: type, value: str, attribut: str
        ) -> Union[int, float]:
            if functype is float:
                typed = value.replace(".", "")
            else:
                typed = value
            if typed.isdigit():
                return functype(value)
            else:
                raise WebScriptsConfigurationError(
                    f"{attribut} must be a list of number ("
                    f"{functype.__name__}) but contain {value!r}"
                )

        if type_ is None:
            type_ = self.__types__.get(attribut)

            if type_ is None or type_ is str:
                setattr(self, attribut, str(value))
                return None

        if isinstance(type_, _GenericAlias) or isinstance(
            type_, _SpecialGenericAlias
        ):
            if isinstance(value, type_.__origin__):
                setattr(self, attribut, value)
                # return None
        else:
            if isinstance(value, type_):
                setattr(self, attribut, value)
                return None

        if type_ is bool:
            if value == "true":
                setattr(self, attribut, True)
            elif value == "false":
                setattr(self, attribut, False)
            else:
                raise WebScriptsConfigurationError(
                    f"{attribut} must be boolean (true or false)"
                    f" but is {value}"
                )

        elif type_ is int or type_ is float:
            if isinstance(value, str):
                setattr(self, attribut, get_number(type_, value, attribut))
            elif type_ is float and isinstance(value, int):
                setattr(self, attribut, float(value))
            else:
                raise WebScriptsConfigurationError(
                    f"{attribut!r} must be an integer but is {value!r}"
                )

        elif type_ is List[str] or type_ is list or type_ is List:
            if isinstance(value, str):
                setattr(self, attribut, value.split(","))
            elif isinstance(value, list):
                type_list = []
                for element in value:
                    if isinstance(element, str):
                        type_list.append(element)
                    else:
                        raise WebScriptsConfigurationError(
                            f"{attribut} must be a list of strings"
                            f" but contain {element!r}"
                        )
                setattr(self, attribut, type_list)

        elif type_ is List[int] or type_ is List[float]:
            functype = type_.__args__[0]
            type_list = []

            if isinstance(value, str):
                for typed in value.split(","):
                    type_list.append(get_number(functype, typed, attribut))
            elif isinstance(value, functype) or (
                functype is float and isinstance(value, int)
            ):
                type_list.append(functype(value))
            elif isinstance(value, list):
                for element in value:
                    if isinstance(element, str):
                        type_list.append(
                            get_number(functype, element, attribut)
                        )
                    elif isinstance(element, functype) or (
                        functype is float and isinstance(element, int)
                    ):
                        type_list.append(functype(element))
                    else:
                        raise WebScriptsConfigurationError(
                            f"{attribut} must be a list of number ("
                            f"{functype.__name__}) but contain {element!r}"
                        )
            else:
                raise WebScriptsConfigurationError(
                    f"{attribut} must be a list of number ("
                    f"{functype.__name__}) but is {value!r}"
                )

            setattr(self, attribut, type_list)

    @log_trace
    def set_defaults(self) -> None:
        """
        This function set defaults attribut with defaults values.
        """

        for attr, value in self.__defaults__.items():
            setattr(self, attr, getattr(self, attr, value))

    @log_trace
    def get(self, key: str, default=None):
        """
        Compatibility with dict.
        """

        return getattr(self, key, default)

    @log_trace
    def __getitem__(self, key: str):
        """
        Compatibility with dict.
        """

        return getattr(self, key)

    @classmethod
    @log_trace
    def default_build(cls, **kwargs) -> DefaultNamespace:
        """
        Default build for DefaultNamespace (set defaults, add values,
        check requirements and unexpected values and build types).
        """

        namespace = cls()
        namespace.set_defaults()
        namespace.update(**kwargs)
        namespace.check_required()
        namespace.get_unexpecteds()
        namespace.build_types()
        return namespace


@log_trace
def get_encodings():
    """
    This function returns the probable encodings.
    """

    encoding = getpreferredencoding()
    if encoding is not None:
        yield encoding

    encoding = device_encoding(0)
    if encoding is not None:
        yield encoding

    yield "utf-8"  # Default for Linux
    yield "cp1252"  # Default for Windows
    yield "latin-1"  # Can read all files
    yield None


@log_trace
def get_ini_dict(filename: str) -> Dict[str, Dict[str, str]]:
    """
    This function return a dict from ini filename.
    """

    config = ConfigParser(allow_no_value=True, inline_comment_prefixes="#")
    config.read(filename)
    return config._sections


@log_trace
def get_ip(
    environ: _Environ, ip_number: int = None, protected: bool = True
) -> str:
    """
    This function return the real IP.
    """

    ips = None
    counter = 0
    check_number = ip_number is not None

    for ip_header in IP_HEADERS:
        ip = environ.get(ip_header)
        if ip is not None:
            ip_length = len(ip.split(", "))
            if protected:
                counter += ip_length

                if check_number and counter > ip_number:
                    logger_critical(f"IP Spoofing detected: {ips}, {ip}.")
                    return None

                if ips:
                    ips += ", " + ip
                else:
                    ips = ip

                logger_debug(f"Header: {ip_header!r} found with ip: {ip!r}")
            else:
                ips = ip
                break

    return ips


@log_trace
def get_file_content(
    file_path, *args, as_iterator: bool = False, **kwargs
) -> StrOrBytes:
    """
    This function return the file content.
    """

    if as_iterator:
        return open(get_real_path(file_path), "rb", *args, **kwargs)

    if "encoding" in kwargs or "rb" in args or "rb" in kwargs.values():
        with open(get_real_path(file_path), *args, **kwargs) as file:
            content = file.read()
        return content

    errors = []
    encodings = get_encodings()
    encoding = next(encodings)
    content = None

    while encoding is not None:
        file = open(
            get_real_path(file_path), *args, encoding=encoding, **kwargs
        )
        try:
            content = file.read()
        except UnicodeDecodeError as e:
            errors.append(e)
        else:
            success = True
        finally:
            success = False if content is None else True
            file.close()

        if success:
            return content

        encoding = next(encodings)

    raise Exception(errors)


@log_trace
def get_arguments_count(object_: Callable):
    """
    This function return the number of argument to call this Callable object.
    """

    obj__get_attr = object_

    for attrs in [
        ["__wrapped__", "__code__"],
        ["__class__", "__call__", "__wrapped__", "__code__"],
        ["__class__", "__call__", "__code__"],
        ["__code__"],
        ["__func__", "__code__"],
    ]:
        for attr in attrs:
            obj__get_attr = getattr(obj__get_attr, attr, None)
            if obj__get_attr is None:
                break

        if isinstance(obj__get_attr, CodeType):
            return obj__get_attr.co_argcount + obj__get_attr.co_kwonlyargcount

        obj__get_attr = object_

    return 7


@log_trace
def get_real_path(
    file_path: str, is_dir: bool = False, no_error: bool = False
) -> str:
    """
    This function return the real path for files.
    """

    if file_path is None:
        return file_path

    if IS_WINDOWS:
        length = 2
        index = 1
        character = ":"
    else:
        length = 1
        index = 0
        character = "/"

    file_path = normcase(file_path)
    server_file_path = join(server_path, file_path)

    if is_dir:
        check = isdir
    else:
        check = isfile

    if check(file_path):
        return abspath(file_path)
    elif (
        len(file_path) > length
        and file_path[index] != character
        and check(server_file_path)
    ):
        return abspath(server_file_path)
    elif no_error:
        return None

    raise FileNotFoundError(
        f"[WebScripts] No such file or directory: '{file_path}'"
    )


@log_trace
def check_file_permission(
    configuration: DefaultNamespace,
    filepath: str,
    recursive: bool = False,
    executable: bool = False,
    dir_check: bool = True,
) -> bool:
    """
    This function checks files and directories permissions for security.
    """

    if not IS_WINDOWS and configuration.force_file_permissions:
        metadata = stat(filepath)
        mode = filemode(metadata.st_mode)
        owner = getpwuid(metadata.st_uid).pw_name

        # frame = _getframe(1)
        # frame = frame.f_back
        # code = frame.f_code

        # print(
        #     "\x1b[31m",
        #     "*" * 50,
        #     filepath + "\t-\t" + code.co_filename
        #         + ":" + str(frame.f_lineno) + ":"
        #         + code.co_name + "\x1b[0m",
        #     sep="\n"
        # )

        if isfile(filepath):
            mode1 = mode[1]
            mode3 = mode[3]

            return_value = (
                mode[0] == "-"
                and (mode1 == "r" or mode1 == "-")
                and mode[2] == "-"
                and ((executable and mode3 == "x") or mode3 == "-")
                and mode.endswith("------")
                and owner == user
            )

            if return_value and dir_check:
                return_value = check_file_permission(
                    configuration, dirname(filepath)
                )

        elif isdir(filepath):
            return_value = mode == "drwxr-xr-x" and owner == "root"

            if recursive and return_value:
                return_value = all(
                    check_file_permission(
                        configuration, x, recursive, executable, False
                    )
                    for x in listdir(filepath)
                )

        if not return_value:
            logger_critical(
                "File permissions are not secure: "
                f"{filepath!r} (owner: {owner!r}, permissions: {mode})"
            )

        return return_value

    else:
        return True


server_path: str = dirname(__file__)
working_directory: str = getcwd()

user: str = getuser()

date_format: str = "%Y-%m-%d %H:%M:%S"
addLevelName(5, "TRACE")
addLevelName(25, "ACCESS")
addLevelName(26, "RESPONSE")
addLevelName(27, "COMMAND")

logger_trace: Callable = Logs.trace
logger_debug: Callable = Logs.debug
logger_info: Callable = Logs.info
logger_access: Callable = Logs.access
logger_response: Callable = Logs.response
logger_command: Callable = Logs.command
logger_warning: Callable = Logs.warning
logger_error: Callable = Logs.error
logger_critical: Callable = Logs.critical
