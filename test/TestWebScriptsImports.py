#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file tests the WebScript.py file
#    from the command line and display the result in a web interface.
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
This file tests specials imports with specific
variables values.
"""

from os import path, rename, chdir, getcwd, mkdir, remove
from unittest.mock import MagicMock, patch, Mock
from contextlib import suppress
from importlib import reload
from platform import system
import logging.config
import subprocess  # nosec
import builtins
import logging
import sys

WebScripts_path = path.join(path.dirname(__file__), "..")
to_remove = []

if not path.exists(
    path.join(WebScripts_path, "webscripts_file_integrity.json")
):
    f = open(path.join(WebScripts_path, "webscripts_file_integrity.json"), "w")
    f.write("{}")
    f.close()
    to_remove.append(
        path.join(WebScripts_path, "webscripts_file_integrity.json")
    )

if not path.exists(path.join(WebScripts_path, "uploads_file_integrity.json")):
    f = open(path.join(WebScripts_path, "uploads_file_integrity.json"), "w")
    f.write("{}")
    f.close()
    to_remove.append(path.join(WebScripts_path, "uploads_file_integrity.json"))

if not path.exists(path.join(WebScripts_path, "logs_checks.json")):
    f = open(path.join(WebScripts_path, "logs_checks.json"), "w")
    f.write("{}")
    f.close()
    to_remove.append(path.join(WebScripts_path, "logs_checks.json"))

if WebScripts_path not in sys.path:
    sys.path.insert(0, WebScripts_path)

argv = sys.argv.copy()
sys.argv = ["WebScripts", "--test-running"]

dir_path = path.dirname(__file__)


def disable_logs():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})
    logging.disable()


def import_without_package():
    ################
    # SAVE VARIABLES
    ################

    path_ = sys.path.copy()
    modules = sys.modules.copy()
    locals_ = locals().copy()
    globals_ = globals().copy()
    current_path = getcwd()
    if not path.exists(path.join(current_path, "logs")):
        mkdir(path.join(current_path, "logs"))
    dst1 = path.join(dir_path, "..", "WebScripts", "__init__.py")
    dst2 = path.join(dir_path, "..", "test", "init.py")

    ########################
    # CHANGE CONTEXT AND SYS
    ########################

    error = None

    try:
        for i in [0, 0, -1, -1]:
            sys.path.pop(i)

        rename(dst1, dst2)
        chdir(path.join(dir_path, "..", "WebScripts"))
        sys.path.insert(0, "")

        for name in [
            "WebScripts",
            "Configuration",
            "Server",
            "WebScriptsConfigurationTypeError",
            "commons",
            "Blacklist",
            "Session",
        ]:
            if name in locals().keys():
                del locals()[name]
            if name in globals().keys():
                del globals()[name]

        remove_names = []
        for name in sys.modules.keys():
            if "WebScripts." in name or name == "WebScripts":
                remove_names.append(name)

        for name in remove_names:
            del sys.modules[name]

        from WebScripts import (
            Configuration,
            Server,
            WebScriptsConfigurationTypeError,
        )
        from commons import Blacklist, Session

    except Exception as e:
        error = e

    #########################
    # REBUILD CONTEXT AND SYS
    #########################
    finally:
        if not path.exists(path.join(getcwd(), "logs")):
            mkdir(path.join(getcwd(), "logs"))

        sys.path = path_
        sys.modules = modules
        rename(dst2, dst1)
        chdir(current_path)

        for name, value in locals_.items():
            locals()[name] = value

        for name, value in globals_.items():
            globals()[name] = value

    if error:
        raise error


# disable_logs()
import_without_package()

from importlib.util import spec_from_file_location, module_from_spec
from os.path import basename, splitext, split, join
from importlib._bootstrap import _exec
from types import ModuleType


def import_from_filename(filename: str) -> ModuleType:
    """
    This function returns a module from path/filename.
    """

    spec = spec_from_file_location(splitext(basename(filename))[0], filename)
    module = module_from_spec(spec)
    module.__spec__ = spec
    spec.loader.exec_module(module)

    return module


class OsModule:
    def __new__(cls):
        import os

        return type("OsModule", (), os.__dict__)

    def __init__(self):
        pass

    @staticmethod
    def mkdir(file):
        raise PermissionError

    class path:
        def __new__(cls):
            import os.path

            return type("PathModule", (), os.path.__dict__)

        def __init__(self):
            pass

        @staticmethod
        def isdir(directory):
            return False


import os
import os.path

sys.modules["os"] = OsModule()
sys.modules["path"] = OsModule.path()
sys.modules["os.path"] = OsModule.path()

sys.modules["os"].mkdir = OsModule.mkdir

with patch.object(
    sys.modules["os.path"], "isdir", return_value=False
), patch.object(sys.modules["path"], "isdir", return_value=False):
    import WebScripts

real_check_file_permission = WebScripts.check_file_permission

WebScripts.check_file_permission = lambda *x, **y: True

WebScripts.configure_logs_system()

sys.modules["utils"] = utils = import_from_filename(
    join(split(WebScripts.__file__)[0], "utils.py")
)
# sys.modules["commons"] = commons = import_from_filename(
#     join(split(WebScripts.__file__)[0], "commons.py")
# )
# sys.modules["hardening"] = hardening = import_from_filename(
#     join(split(WebScripts.__file__)[0], "hardening.py")
# )

# utils2 = sys.modules.get("WebScripts.utils", utils)
# commons2 = sys.modules.get("WebScripts.commons", commons)
# hardening2 = sys.modules.get("WebScripts.hardening", hardening)

# utils2.check_file_permission = commons2.check_file_permission = utils.check_file_permission = commons.check_file_permission = lambda *x, **y: True
IS_WINDOWS = utils.IS_WINDOWS
# utils2.IS_WINDOWS = utils.IS_WINDOWS = True


def get_pourcent(self) -> None:
    self.pourcent = {s.value: 0 for s in hardening2.SEVERITY}
    self.pourcent["ALL"] = 0
    print("*" * 50)


# real_get_pourcent = hardening2.Report.get_pourcent
# hardening2.Report.get_pourcent = hardening.Report.get_pourcent = get_pourcent

WebScripts.argv = sys.argv = ["WebScripts", "--debug", "--active-auth"]

# print("", *dir(WebScripts), sep="\n")
# print(WebScripts.isdir)
# print(WebScripts.mkdir)

WebScripts.mkdir = OsModule.mkdir
# print(WebScripts.mkdir)
WebScripts.main.__globals__["get_ip"].__globals__[
    "check_file_permission"
] = lambda *x, **y: True
WebScripts.main.__globals__["get_ip"].__globals__["IS_WINDOWS"] = True
daemon_func = WebScripts.main.__globals__["hardening"].__globals__[
    "daemon_func"
]
WebScripts.main.__globals__["hardening"].__globals__["daemon_func"] = Mock()
simple_server = WebScripts.main.__globals__["simple_server"]
WebScripts.main.__globals__["simple_server"] = Mock()
with patch.object(WebScripts, "isdir", return_value=False):
    WebScripts.main()

# hardening2.Report.get_pourcent = hardening.Report.get_pourcent = real_get_pourcent
# utils2.check_file_permission = commons2.check_file_permission = utils.check_file_permission = commons.check_file_permission = WebScripts.check_file_permission = real_check_file_permission
sys.argv = argv
# utils2.IS_WINDOWS = utils.IS_WINDOWS = IS_WINDOWS
WebScripts.main.__globals__["get_ip"].__globals__[
    "check_file_permission"
] = real_check_file_permission
WebScripts.main.__globals__["get_ip"].__globals__["IS_WINDOWS"] = IS_WINDOWS
WebScripts.main.__globals__["hardening"].__globals__[
    "daemon_func"
] = daemon_func
WebScripts.main.__globals__["simple_server"] = simple_server

sys.modules["win32evtlogutil"] = Mock(ReportEvent=Mock())
sys.modules["win32security"] = Mock(
    OpenProcessToken=Mock(),
    GetTokenInformation=Mock(return_value=[Mock()]),
    TokenUser=Mock(),
)
sys.modules["win32api"] = Mock(GetCurrentProcess=Mock())
sys.modules["win32con"] = Mock(TOKEN_READ=Mock())
sys.modules["win32evtlog"] = Mock(
    EVENTLOG_INFORMATION_TYPE=Mock(),
    EVENTLOG_WARNING_TYPE=Mock(),
    EVENTLOG_ERROR_TYPE=Mock(),
)
_exec(utils.__spec__, utils)


class ModuleTest:
    @property
    def ReportEvent(self):
        raise ImportError("test")

    def __getattr__(self):
        raise ImportError("test")

    def __getattribute__(self):
        raise ImportError("test")


from inspect import stack


def change_WINDOWS_LOGS(*args):
    module_caller_globals = stack()[1].frame.f_globals
    print("*" * 150)
    print(module_caller_globals)
    print("*" * 150)
    module_caller_globals["WINDOWS_LOGS"] = False


sys.modules["win32evtlogutil"] = ModuleTest()
# from win32evtlogutil import ReportEvent
del sys.modules["win32con"]
del sys.modules["win32api"]
del sys.modules["win32evtlog"]
sys.modules["win32security"] = Mock()
sys.modules["win32security"].GetTokenInformation = change_WINDOWS_LOGS
# sys_path = sys.path
# path_importer = sys.path_importer_cache.copy()
# path_hooks = sys.path_hooks
# meta_path = sys.meta_path

# def clear_path():
#     sys.path = []
#     sys.path_importer_cache.clear()
#     sys.path_hooks = []
#     sys.modules = {k: v for k, v in sys.modules.items() if "win" not in k}
#     sys.meta_path = []
#     return "Windows"

# sys.modules["platform"].system = clear_path
_exec(utils.__spec__, utils)
exec(open(utils.__file__).read())  # nosec

# sys.path = sys_path
# sys.path_importer_cache = path_importer
# sys.path_hooks = path_hooks
# sys.meta_path = meta_path

# print(sys.path, list(sys.modules.keys()))

sys.modules["syslog"] = Mock(
    syslog=Mock(),
    LOG_DEBUG=Mock(),
    LOG_INFO=Mock(),
    LOG_WARNING=Mock(),
    LOG_ERR=Mock(),
    LOG_CRIT=Mock(),
)
sys.modules["pwd"] = Mock(
    getpwuid=Mock(),
)
# sys.modules["platform"].system = (
#     lambda *x, **y: "Linux" if system() == "Windows" else "Windows"
# )

with patch.object(
    sys.modules["platform"],
    "system",
    return_value=("Linux" if system() == "Windows" else "Windows"),
), patch.object(
    sys.modules["subprocess"],
    "check_call",
    return_value=0,
):
    utils.get_real_path("/test/whynot", no_error=True)
    _exec(utils.__spec__, utils)

# sys.modules["platform"].system = system

with patch.object(
    sys.modules["subprocess"],
    "check_call",
    return_value=0,
):
    _exec(utils.__spec__, utils)

sys.argv = ["exe", "--test-running"]
__import__(
    "WebScripts",
    {"__name__": "__main__"},
    {"__name__": "__main__"},
)

global_ = globals().copy()
local_ = locals().copy()

local_["__name__"] = "__main__"
global_["__name__"] = "__main__"

# exec(open(WebScripts.__file__).read(), locals=local_, globals=global_)
