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
import subprocess
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


disable_logs()
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
    def mkdir():
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


sys.modules["os"] = OsModule()
sys.modules["path"] = OsModule.path()
sys.modules["os.path"] = OsModule.path()

import WebScripts

WebScripts.configure_logs_system()

sys.modules["utils"] = utils = import_from_filename(
    join(split(WebScripts.__file__)[0], "utils.py")
)

sys.argv = ["WebScripts", "--debug"]
WebScripts.main()
sys.argv = argv

for file in to_remove:
    remove(file)

sys.modules["win32evtlogutil"] = Mock(ReportEvent=object)
sys.modules["win32evtlog"] = Mock()
_exec(utils.__spec__, utils)


class ModuleTest:
    @property
    def ReportEvent(self):
        raise ImportError


sys.modules["win32evtlogutil"] = ModuleTest()
_exec(utils.__spec__, utils)

sys.modules["syslog"] = Mock(syslog=object)
# sys.modules["platform"].system = (
#     lambda *x, **y: "Linux" if system() == "Windows" else "Windows"
# )

with patch.object(
    sys.modules["platform"],
    "system",
    return_value=("Linux" if system() == "Windows" else "Windows"),
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
